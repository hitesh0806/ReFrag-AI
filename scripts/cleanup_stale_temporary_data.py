import os
import sys
import argparse

# Dynamically resolve project root and backend dir
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(script_dir)
backend_dir = os.path.join(project_root, "backend")

if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

os.chdir(backend_dir)

from app.db.database import SessionLocal
from app.models.forensic import (
    ForensicCase,
    ForensicArtifact,
    ForensicFragment,
    FragmentRelationship,
    ReconstructionCandidate
)

def cleanup_temporary_data(case_id: str = None, all_completed: bool = False, purge_all_stale: bool = False):
    """
    DEVELOPMENT-ONLY CLEANUP UTILITY:
    Purges temporary processing tables (fragment_relationships, forensic_fragments).
    Strictly PRESERVES:
      - forensic_cases (case metadata, status, created_at)
      - forensic_artifacts (original uploaded evidence bytes, sha256, files)
      - reconstruction_candidates (final reconstructed JPEG byte stream, validation results)
    """
    db = SessionLocal()
    try:
        print("=" * 65)
        print("  REFRAG AI - DEVELOPMENT TEMPORARY DATA PURGE UTILITY")
        print("=" * 65)

        total_cases_before = db.query(ForensicCase).count()
        total_artifacts_before = db.query(ForensicArtifact).count()
        total_candidates_before = db.query(ReconstructionCandidate).count()
        total_fragments_before = db.query(ForensicFragment).count()
        total_relationships_before = db.query(FragmentRelationship).count()

        print("--- CURRENT DATABASE STATE (BEFORE PURGE) ---")
        print(f"  • forensic_cases            : {total_cases_before} records (EVIDENCE METADATA)")
        print(f"  • forensic_artifacts        : {total_artifacts_before} records (ORIGINAL EVIDENCE BYTES)")
        print(f"  • reconstruction_candidates : {total_candidates_before} records (FINAL RESULTS)")
        print(f"  • forensic_fragments        : {total_fragments_before} records [TEMPORARY PROCESSING DATA]")
        print(f"  • fragment_relationships    : {total_relationships_before} records [TEMPORARY PROCESSING DATA]")
        print("-" * 65)

        target_case_ids = []
        if case_id:
            case = db.query(ForensicCase).filter(ForensicCase.id == case_id).first()
            if not case:
                print(f"[!] Error: Case '{case_id}' does not exist.")
                return
            target_case_ids = [case_id]
            print(f"[*] Targeting specific case: {case_id} (Status: {case.status})")
        elif all_completed:
            cases = db.query(ForensicCase.id).filter(ForensicCase.status == "COMPLETED").all()
            target_case_ids = [c[0] for c in cases]
            print(f"[*] Targeting {len(target_case_ids)} COMPLETED cases.")
        elif purge_all_stale:
            # Purge all completed or old testing cases
            target_case_ids = None
            print("[*] Targeting ALL temporary processing tables across all test runs.")
        else:
            # Default: target completed cases or prompt
            cases = db.query(ForensicCase.id).filter(ForensicCase.status == "COMPLETED").all()
            target_case_ids = [c[0] for c in cases]
            print(f"[*] Default mode: Targeting {len(target_case_ids)} COMPLETED cases.")

        print("\n--- EXECUTING SAFE PURGE IN STRICT FOREIGN KEY ORDER ---")
        print("Step 1: Purging fragment_relationships (child table)...")
        if target_case_ids is not None:
            del_rel = db.query(FragmentRelationship).filter(
                FragmentRelationship.case_id.in_(target_case_ids)
            ).delete(synchronize_session=False)
        else:
            del_rel = db.query(FragmentRelationship).delete(synchronize_session=False)

        print(f"        -> Removed {del_rel} temporary relationship rows.")

        print("Step 2: Purging forensic_fragments (parent processing table)...")
        if target_case_ids is not None:
            del_frag = db.query(ForensicFragment).filter(
                ForensicFragment.case_id.in_(target_case_ids)
            ).delete(synchronize_session=False)
        else:
            del_frag = db.query(ForensicFragment).delete(synchronize_session=False)

        print(f"        -> Removed {del_frag} temporary fragment rows.")

        db.commit()

        # Post-purge verification
        total_cases_after = db.query(ForensicCase).count()
        total_artifacts_after = db.query(ForensicArtifact).count()
        total_candidates_after = db.query(ReconstructionCandidate).count()
        total_fragments_after = db.query(ForensicFragment).count()
        total_relationships_after = db.query(FragmentRelationship).count()

        print("\n--- INTEGRITY AUDIT AFTER PURGE ---")
        print(f"  • forensic_cases            : {total_cases_after} records (Unchanged: {total_cases_before == total_cases_after})")
        print(f"  • forensic_artifacts        : {total_artifacts_after} records (Unchanged: {total_artifacts_before == total_artifacts_after})")
        print(f"  • reconstruction_candidates : {total_candidates_after} records (Unchanged: {total_candidates_before == total_candidates_after})")
        print(f"  • forensic_fragments        : {total_fragments_after} records (Remaining temporary)")
        print(f"  • fragment_relationships    : {total_relationships_after} records (Remaining temporary)")

        assert total_cases_before == total_cases_after, "SAFETY VIOLATION: Cases were modified!"
        assert total_artifacts_before == total_artifacts_after, "SAFETY VIOLATION: Original artifacts were modified!"
        assert total_candidates_before == total_candidates_after, "SAFETY VIOLATION: Candidates were modified!"

        print("\n[OK] SUCCESS: All original evidence and final reconstructions verified intact.")
        print("[OK] Temporary processing overhead eliminated.")
        print("=" * 65)

    except Exception as e:
        db.rollback()
        print(f"[!] Purge error: {e}")
        raise
    finally:
        db.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Purge temporary forensic processing tables.")
    parser.add_argument("--case-id", help="Scope cleanup to a specific case ID")
    parser.add_argument("--all-completed", action="store_true", help="Clean temporary data for all COMPLETED cases")
    parser.add_argument("--purge-all-stale", action="store_true", help="Purge all temporary processing tables across all test runs")
    args = parser.parse_args()

    cleanup_temporary_data(
        case_id=args.case_id,
        all_completed=args.all_completed,
        purge_all_stale=args.purge_all_stale
    )
