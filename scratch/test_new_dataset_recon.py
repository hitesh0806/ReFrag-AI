import os
import sys
import glob
import hashlib
import io
from PIL import Image

sys.path.insert(0, "backend")
from app.db.database import SessionLocal
from app.models.forensic import ForensicCase, ForensicArtifact, ForensicFragment, FragmentRelationship, ReconstructionCandidate
from app.services.fragment_relationship_service import FragmentRelationshipService
from app.services.reconstruction_service import ReconstructionService

def run():
    db = SessionLocal()
    case_id = "CASE-NEW-DATASET-TEST"

    # Remove if existing
    old = db.query(ForensicCase).filter(ForensicCase.id == case_id).first()
    if old:
        db.delete(old)
        db.commit()

    case = ForensicCase(id=case_id, case_name="Controlled Benchmark (12 Target + 8 Decoys)", status="ingested")
    db.add(case)
    db.flush()

    files = glob.glob("test_dataset/mixed_dataset/*.bin")
    print(f"1. Ingesting {len(files)} fragments into {case_id}...")
    assert len(files) == 20, f"Expected 20 files, found {len(files)}"

    for fpath in files:
        fname = os.path.basename(fpath)
        with open(fpath, "rb") as f:
            content = f.read()
        art = ForensicArtifact(
            case_id=case_id,
            original_filename=fname,
            relative_path=f"mixed_dataset/{fname}",
            file_size=len(content),
            sha256_hash=hashlib.sha256(content).hexdigest(),
            content=content
        )
        db.add(art)

    case.total_files = len(files)
    case.total_size = sum(os.path.getsize(p) for p in files)
    db.commit()

    print("\n2. Analyzing fragments...")
    frags = FragmentRelationshipService.analyze_case_fragments(db, case_id)
    print(f"Analyzed {len(frags)} fragments.")

    print("\n3. Computing directed pairwise relationships...")
    rels = FragmentRelationshipService.compute_case_relationships(db, case_id)
    print(f"Computed {len(rels)} relationships.")

    print("\n4. Running reconstruction engine...")
    cands = ReconstructionService.reconstruct_case(db, case_id)
    assert len(cands) > 0, "No reconstruction candidates generated!"
    top = cands[0]

    print(f"\n--- RECONSTRUCTION RESULTS ---")
    print(f"Status              : {top.status}")
    print(f"Confidence          : {top.confidence:.1%}")
    print(f"Fragment Count      : {top.fragment_count}")
    print(f"Reconstructed Size  : {top.reconstructed_size} bytes")

    vr = top.validation_result or {}
    chain_names = vr.get("ordered_filenames") or [n["filename"] for n in vr.get("chain_details", [])]
    print(f"\nReconstruction Path :")
    for i, name in enumerate(chain_names):
        print(f"  [{i+1:02d}] {name}")

    raw_bytes = top.reconstructed_content
    calc_sha = hashlib.sha256(raw_bytes).hexdigest()
    expected_sha = "16d58d65661324944b193a641b6bacf02ab549c4c9e80f234a5ce90de3a48d2b"
    print(f"\nReconstructed SHA256: {calc_sha}")
    print(f"Expected Target SHA : {expected_sha}")
    print(f"Byte Exact Match    : {calc_sha == expected_sha}")

    assert top.fragment_count == 12, f"Expected 12 fragments, got {top.fragment_count}"
    assert top.reconstructed_size == 43202, f"Expected 43202 bytes, got {top.reconstructed_size}"
    assert calc_sha == expected_sha, "Reconstructed SHA-256 does NOT match target ground truth!"

    # Verify image opens cleanly
    img = Image.open(io.BytesIO(raw_bytes))
    img.verify()
    img2 = Image.open(io.BytesIO(raw_bytes))
    img2.load()
    print(f"Image decoded cleanly: {img2.width}x{img2.height}, mode={img2.mode}")
    assert img2.width == 1200 and img2.height == 750

    # Verify rejected fragments
    vr = top.validation_result or {}
    rej = vr.get("rejected_fragments", [])
    print(f"\nRejected Fragments Count: {len(rej)}")
    assert len(rej) == 8, f"Expected 8 rejected fragments, got {len(rej)}"
    for r in rej:
        print(f"  * {r['filename']}: {r['reason']}")

    print("\nSUCCESS: All forensic checks passed! Target JPEG perfectly reconstructed, all decoys rejected!")

if __name__ == "__main__":
    run()
