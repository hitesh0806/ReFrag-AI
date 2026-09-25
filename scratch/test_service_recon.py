import os
import sys
import time

sys.path.insert(0, 'backend')
from app.db.database import SessionLocal
from app.services.reconstruction_service import ReconstructionService
from app.models.forensic import ForensicFragment

db = SessionLocal()
case_id = 'CASE-NEW-DATASET-TEST'
t0 = time.time()
print(f'Starting ReconstructionService.reconstruct_case on {case_id}...')
cands = ReconstructionService.reconstruct_case(db, case_id)
print(f'Completed in {time.time()-t0:.2f}s, candidates returned: {len(cands)}')

if not cands:
    print('ERROR: No candidates returned!')
    sys.exit(1)

top = cands[0]
print(f'Top Candidate Status  : {top.status}')
print(f'Integrity Score       : {top.integrity_score}')
print(f'Confidence            : {top.confidence}')
print(f'Reconstructed Size    : {top.reconstructed_size} bytes')
print(f'Fragment Count        : {top.fragment_count}')

frags = db.query(ForensicFragment).filter(ForensicFragment.case_id == case_id).all()
fmap = {f.id: f.source_filename for f in frags}
order_names = [fmap[x] for x in top.fragment_order]

print('\nInferred Sequence:')
for i, name in enumerate(order_names):
    print(f'  {i+1:02d}: {name}')

vr = top.validation_result or {}
print('\nValidation Metrics:')
print(f'  Decoder Valid           : {vr.get("decoder_valid")}')
print(f'  Structurally Parseable  : {vr.get("structurally_parseable")}')
print(f'  Dev Verification        : {vr.get("dev_verification")}')
print(f'  Exact SHA-256 Match     : {vr.get("exact_sha_match")}')
print(f'  Reconstructed SHA-256   : {vr.get("calculated_sha256")}')
print(f'  Target Ground Truth SHA : {vr.get("target_sha256")}')
print(f'  Selected Fragments      : {vr.get("selected_fragments_count")}')
print(f'  Rejected Fragments      : {vr.get("rejected_fragments_count")}')

print('\nRejected Decoys Forensic Breakdown:')
for rf in vr.get('rejected_fragments', []):
    print(f'  * {rf["filename"]}: {rf["reason"]}')

if vr.get("dev_verification") == "PASS":
    print('\n>>> DEVELOPMENT VERIFICATION: PASS <<<')
else:
    print('\n>>> DEVELOPMENT VERIFICATION: FAIL <<<')
