import os
import sys
import glob
import hashlib
from fastapi.testclient import TestClient

# Ensure root & backend in path
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(script_dir)
backend_dir = os.path.join(project_root, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

os.chdir(backend_dir)

from app.main import app
from app.db.database import SessionLocal
from app.models.forensic import (
    ForensicCase,
    ForensicArtifact,
    ForensicFragment,
    FragmentRelationship,
    ReconstructionCandidate
)
from app.services.fragment_relationship_service import FragmentRelationshipService
from app.services.reconstruction_service import ReconstructionService

def test_acceptance_lifecycle():
    print("=" * 70)
    print(" ACCEPTANCE TEST SUITE: FORENSIC DATABASE LIFECYCLE & CLEANUP")
    print("=" * 70)

    db = SessionLocal()
    frag_files = glob.glob(os.path.join(project_root, "test_dataset", "shuffled_fragments", "*.bin"))
    if not frag_files:
        raise RuntimeError("Test dataset shuffled_fragments not found!")

    # Step 1: Upload mixed JPEG fragment dataset
    print("\n[STEP 1] Ingesting dataset into a new forensic case...")
    case = ForensicCase(case_name="Lifecycle Acceptance Test Case", status="UPLOADED")
    db.add(case)
    db.flush()
    case_id = case.id

    uploaded_hashes = set()
    total_size = 0
    for p in frag_files:
        fname = os.path.basename(p)
        with open(p, "rb") as f:
            content = f.read()
        sha = hashlib.sha256(content).hexdigest()
        uploaded_hashes.add(sha)
        total_size += len(content)

        art = ForensicArtifact(
            case_id=case_id,
            original_filename=fname,
            relative_path=f"shuffled_fragments/{fname}",
            file_size=len(content),
            sha256_hash=sha,
            content=content
        )
        db.add(art)

    case.total_files = len(frag_files)
    case.total_size = total_size
    db.commit()
    print(f" -> Case ID created: {case_id} ({len(frag_files)} files, {total_size} bytes)")

    # Step 2: Verify forensic_artifacts contains uploaded evidence
    print("\n[STEP 2] Verifying forensic_artifacts contains original uploaded evidence...")
    artifact_count = db.query(ForensicArtifact).filter(ForensicArtifact.case_id == case_id).count()
    assert artifact_count == len(frag_files), f"Expected {len(frag_files)} artifacts, found {artifact_count}"
    print(f" [PASS] Exactly {artifact_count} original evidence artifacts stored.")

    # Step 3: Start analysis
    print("\n[STEP 3] Starting fragment and relationship analysis...")
    frags = FragmentRelationshipService.analyze_case_fragments(db, case_id)
    rels = FragmentRelationshipService.compute_case_relationships(db, case_id)

    # Step 4 & 5: Verify temporary tables are populated during processing
    print("\n[STEP 4 & 5] Checking temporary tables during processing...")
    temp_frags_count = db.query(ForensicFragment).filter(ForensicFragment.case_id == case_id).count()
    temp_rels_count = db.query(FragmentRelationship).filter(FragmentRelationship.case_id == case_id).count()
    print(f" -> Temporary forensic_fragments count    : {temp_frags_count}")
    print(f" -> Temporary fragment_relationships count: {temp_rels_count}")
    assert temp_frags_count == len(frag_files), f"Expected {len(frag_files)} temporary fragments, got {temp_frags_count}"
    assert temp_rels_count > 0, "Expected relationships to be populated"
    print(" [PASS] Temporary processing tables populated successfully.")

    # Step 6, 7, 8, 9: Reconstruction & Validation with automated cleanup
    print("\n[STEP 6, 7, 8, 9] Executing reconstruction, validation, and atomic cleanup...")
    cands = ReconstructionService.reconstruct_case(db, case_id)
    assert len(cands) == 1, f"Expected 1 reconstruction candidate, got {len(cands)}"
    cand = cands[0]

    print(f" -> Candidate Status        : {cand.status}")
    print(f" -> Integrity Score         : {cand.integrity_score}")
    print(f" -> Calibrated Confidence   : {cand.confidence:.2%}")
    print(f" -> Reconstructed JPEG Size : {cand.reconstructed_size} bytes")
    print(f" -> Target Chain Members    : {cand.fragment_count} fragments")

    assert cand.status == "VALIDATED", f"Expected VALIDATED, got {cand.status}"
    assert cand.reconstructed_content is not None and len(cand.reconstructed_content) > 0
    assert cand.reconstructed_content[:2] == b"\xFF\xD8", "SOI missing"
    assert cand.reconstructed_content[-2:] == b"\xFF\xD9", "EOI missing"
    print(" [PASS] Reconstruction and validation succeeded.")

    # Step 10: Query forensic_fragments for that case -> Expected: 0 rows
    print("\n[STEP 10] Querying forensic_fragments for this case...")
    final_frags_count = db.query(ForensicFragment).filter(ForensicFragment.case_id == case_id).count()
    print(f" -> Resulting forensic_fragments row count: {final_frags_count}")
    assert final_frags_count == 0, f"Expected 0 temporary fragments, found {final_frags_count}"
    print(" [PASS] forensic_fragments has 0 rows.")

    # Step 11: Query fragment_relationships for that case -> Expected: 0 rows
    print("\n[STEP 11] Querying fragment_relationships for this case...")
    final_rels_count = db.query(FragmentRelationship).filter(FragmentRelationship.case_id == case_id).count()
    print(f" -> Resulting fragment_relationships row count: {final_rels_count}")
    assert final_rels_count == 0, f"Expected 0 temporary relationships, found {final_rels_count}"
    print(" [PASS] fragment_relationships has 0 rows.")

    # Step 12: Query forensic_artifacts -> Expected: Original uploaded artifacts STILL EXIST
    print("\n[STEP 12] Verifying original forensic_artifacts remain completely intact...")
    final_artifact_count = db.query(ForensicArtifact).filter(ForensicArtifact.case_id == case_id).count()
    print(f" -> forensic_artifacts row count: {final_artifact_count}")
    assert final_artifact_count == len(frag_files), f"Expected {len(frag_files)} artifacts, found {final_artifact_count}"

    # Verify sha256 hashes and contents
    persisted_artifacts = db.query(ForensicArtifact).filter(ForensicArtifact.case_id == case_id).all()
    for art in persisted_artifacts:
        assert art.content is not None and len(art.content) == art.file_size
        assert hashlib.sha256(art.content).hexdigest() == art.sha256_hash
    print(" [PASS] All original uploaded evidence artifacts are 100% intact and verified.")

    # Step 13: Query reconstruction_candidates -> Expected: Final reconstruction STILL EXISTS
    print("\n[STEP 13] Verifying reconstruction_candidates remains intact...")
    final_cand_count = db.query(ReconstructionCandidate).filter(ReconstructionCandidate.case_id == case_id).count()
    assert final_cand_count == 1, f"Expected 1 candidate, found {final_cand_count}"
    persisted_cand = db.query(ReconstructionCandidate).filter(ReconstructionCandidate.case_id == case_id).first()
    assert persisted_cand.reconstructed_size == cand.reconstructed_size
    assert persisted_cand.reconstructed_content == cand.reconstructed_content
    # Check chain_details inside candidate
    assert persisted_cand.validation_result.get("chain_details") is not None
    assert len(persisted_cand.validation_result["chain_details"]) == persisted_cand.fragment_count
    print(f" -> Verified candidate retained {len(persisted_cand.validation_result['chain_details'])} chain details nodes.")
    print(" [PASS] Final reconstruction candidate remains safely preserved.")

    # Step 14: Refresh the frontend / API endpoints -> Expected: View & download still work without fragments
    print("\n[STEP 14] Testing HTTP API endpoints (frontend view / download / candidate details)...")
    client = TestClient(app)

    # 14a. Reconstructions list
    res_list = client.get(f"/api/forensics/cases/{case_id}/reconstructions")
    assert res_list.status_code == 200, f"Failed: {res_list.status_code}"
    cand_json = res_list.json()[0]
    assert len(cand_json["chain_details"]) == cand.fragment_count
    assert cand_json["confidence"] == cand.confidence
    print(" [PASS] GET /cases/{case_id}/reconstructions succeeded with full chain details.")

    # 14b. Fragments endpoint returns clean empty array without error
    res_frags = client.get(f"/api/forensics/cases/{case_id}/fragments")
    assert res_frags.status_code == 200
    assert res_frags.json() == []
    print(" [PASS] GET /cases/{case_id}/fragments returned [] (no crash, purged).")

    # 14c. View inline endpoint
    res_view = client.get(f"/api/forensics/reconstructions/{cand.id}/view")
    assert res_view.status_code == 200
    assert res_view.headers["content-type"] == "image/jpeg"
    assert len(res_view.content) == cand.reconstructed_size
    print(" [PASS] GET /reconstructions/{id}/view served valid reconstructed JPEG inline.")

    # 14d. Download endpoint
    res_dl = client.get(f"/api/forensics/reconstructions/{cand.id}/download")
    assert res_dl.status_code == 200
    assert res_dl.headers["content-type"] == "image/jpeg"
    assert len(res_dl.content) == cand.reconstructed_size
    print(" [PASS] GET /reconstructions/{id}/download returned full reconstructed image attachment.")

    # Step 15: Test development cleanup endpoint
    print("\n[STEP 15] Testing DELETE /api/forensics/cases/{case_id}/temporary-data...")
    res_del = client.delete(f"/api/forensics/cases/{case_id}/temporary-data")
    assert res_del.status_code == 200
    assert res_del.json()["status"] == "success"
    print(" [PASS] DELETE /cases/{case_id}/temporary-data executed successfully.")

    # Step 16: Verify repeated analysis lifecycle
    print("\n[STEP 16] Testing Repeated Analysis Lifecycle (re-analyzing case)...")
    re_frags = FragmentRelationshipService.analyze_case_fragments(db, case_id)
    assert len(re_frags) == len(frag_files)
    count_now = db.query(ForensicFragment).filter(ForensicFragment.case_id == case_id).count()
    assert count_now == len(frag_files), "Repeated analysis should recreate fresh set without duplicates"
    # Reconstruct again
    re_cands = ReconstructionService.reconstruct_case(db, case_id)
    assert len(re_cands) == 1
    # Verify cleaned again
    assert db.query(ForensicFragment).filter(ForensicFragment.case_id == case_id).count() == 0
    assert db.query(FragmentRelationship).filter(FragmentRelationship.case_id == case_id).count() == 0
    assert db.query(ForensicArtifact).filter(ForensicArtifact.case_id == case_id).count() == len(frag_files)
    print(" [PASS] Repeated analysis guard works seamlessly.")

    db.close()
    print("\n" + "=" * 70)
    print(" [ALL 16 ACCEPTANCE CHECKS PASSED SUCCESSFULLY]")
    print("=" * 70)

if __name__ == "__main__":
    test_acceptance_lifecycle()
