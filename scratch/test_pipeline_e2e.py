import os
import sys
import glob
import hashlib

# Ensure backend is in path
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(script_dir)
backend_dir = os.path.join(project_root, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

os.chdir(backend_dir)

from app.db.database import SessionLocal
from app.models.forensic import ForensicCase, ForensicArtifact, ForensicFragment, FragmentRelationship, ReconstructionCandidate
from app.services.fragment_relationship_service import FragmentRelationshipService
from app.services.reconstruction_service import ReconstructionService
from scripts.generate_shuffled_fragments import evaluate_reconstruction

def run():
    db = SessionLocal()
    case = ForensicCase(case_name="Automated E2E JPEG Benchmark Test", status="ingested")
    db.add(case)
    db.flush()

    frag_files = glob.glob(os.path.join(project_root, "test_dataset", "shuffled_fragments", "*.bin"))
    print(f"Ingesting {len(frag_files)} fragments into case {case.id}...")

    for p in frag_files:
        fname = os.path.basename(p)
        with open(p, "rb") as f:
            content = f.read()
        art = ForensicArtifact(
            case_id=case.id,
            original_filename=fname,
            relative_path=f"shuffled_fragments/{fname}",
            file_size=len(content),
            sha256_hash=hashlib.sha256(content).hexdigest(),
            content=content
        )
        db.add(art)

    case.total_files = len(frag_files)
    case.total_size = sum(os.path.getsize(p) for p in frag_files)
    db.commit()

    print("\n--- STEP 1: ANALYZE FRAGMENTS ---")
    frags = FragmentRelationshipService.analyze_case_fragments(db, case.id)
    for f in frags:
        marker_list = [m["name"] for m in f.jpeg_markers or []]
        print(f"  • {f.source_filename} | Class: {f.classification:<22} | Markers: {marker_list} | Entropy: {f.entropy}")

    print("\n--- STEP 2: COMPUTE RELATIONSHIPS ---")
    rels = FragmentRelationshipService.compute_case_relationships(db, case.id)
    print(f"Total directed relationships evaluated: {len(rels)}")
    top_rels = sorted(rels, key=lambda r: r.total_score, reverse=True)[:8]
    for r in top_rels:
        from_name = next(f.source_filename for f in frags if f.id == r.from_fragment_id)
        to_name = next(f.source_filename for f in frags if f.id == r.to_fragment_id)
        print(f"  • {from_name} -> {to_name} : Score = {r.total_score:.3f} (struct: {r.structural_score:.2f}, bound: {r.boundary_score:.2f}, parser: {r.parser_score:.2f})")

    print("\n--- STEP 3: RECONSTRUCT & VALIDATE ---")
    cands = ReconstructionService.reconstruct_case(db, case.id)
    print(f"Reconstruction candidates generated: {len(cands)}")
    top_cand = cands[0]
    
    # Retrieve sequence directly from persisted validation_result chain_details
    val_res = top_cand.validation_result or {}
    ordered_names = val_res.get("ordered_filenames") or [n["filename"] for n in val_res.get("chain_details", [])]
    
    print(f"Candidate Status  : {top_cand.status}")
    print(f"Integrity Score   : {top_cand.integrity_score}")
    print(f"Confidence        : {top_cand.confidence}")
    print(f"Reconstructed Size: {top_cand.reconstructed_size} bytes")
    print(f"Inferred Sequence : {' -> '.join(ordered_names)}")

    print("\n--- STEP 4: DATABASE LIFECYCLE & CLEANUP AUDIT ---")
    frags_remaining = db.query(ForensicFragment).filter(ForensicFragment.case_id == case.id).count()
    rels_remaining = db.query(FragmentRelationship).filter(FragmentRelationship.case_id == case.id).count()
    artifacts_remaining = db.query(ForensicArtifact).filter(ForensicArtifact.case_id == case.id).count()
    cands_remaining = db.query(ReconstructionCandidate).filter(ReconstructionCandidate.case_id == case.id).count()
    
    print(f"  • Temporary forensic_fragments      : {frags_remaining} (Expected: 0)")
    print(f"  • Temporary fragment_relationships  : {rels_remaining} (Expected: 0)")
    print(f"  • Original forensic_artifacts       : {artifacts_remaining} (Expected: {len(frag_files)})")
    print(f"  • Final reconstruction_candidates   : {cands_remaining} (Expected: 1)")

    assert frags_remaining == 0, f"Expected 0 temporary fragments, found {frags_remaining}"
    assert rels_remaining == 0, f"Expected 0 temporary relationships, found {rels_remaining}"
    assert artifacts_remaining == len(frag_files), "Original evidence was modified!"
    assert cands_remaining == 1, "Final reconstruction candidate missing!"
    print("  [OK] Database lifecycle verified: Temporary processing data purged, original evidence preserved.")

    print("\n--- STEP 5: GROUND TRUTH BENCHMARK EVALUATION ---")
    manifest_path = os.path.join(project_root, "test_dataset", "ground_truth_manifest.json")
    evaluate_reconstruction(
        manifest_path=manifest_path,
        reconstructed_order_filenames=ordered_names,
        reconstructed_bytes=top_cand.reconstructed_content
    )

if __name__ == "__main__":
    run()
