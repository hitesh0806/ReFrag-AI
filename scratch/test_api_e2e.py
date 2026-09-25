import os
import sys
import hashlib
import io
from PIL import Image

sys.path.insert(0, "backend")
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

print("1. Testing POST /api/forensics/cases/CASE-2D4A71D6/reconstruct ...")
resp = client.post("/api/forensics/cases/CASE-2D4A71D6/reconstruct")
print("Response status:", resp.status_code)
assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

data = resp.json()
assert len(data) > 0, "No reconstruction candidates returned"
recon = data[0]

print("Status:", recon.get("status"))
print("Confidence:", recon.get("confidence"))
print("Fragment count:", recon.get("fragment_count"))
print("Reconstructed size:", recon.get("reconstructed_size"))
print("Rejected fragments count:", len(recon.get("rejected_fragments", [])))

vr = recon.get("validation_result", {})
print("Validation exact_sha_match:", vr.get("exact_sha_match"))
print("Calculated SHA256:", vr.get("calculated_sha256"))
print("Target SHA256:", vr.get("target_sha256"))
print("Decoded MCUs:", vr.get("decoded_mcus"), "/", vr.get("expected_mcus"))

# Assertions per requirements:
assert recon.get("status") == "VALIDATED", f"Status must be VALIDATED, got {recon.get('status')}"
assert recon.get("fragment_count") == 12, f"Fragment count must be 12, got {recon.get('fragment_count')}"
assert recon.get("reconstructed_size") == 43202, f"Reconstructed size must be 43202, got {recon.get('reconstructed_size')}"
assert vr.get("exact_sha_match") is True, "Exact SHA-256 match must be True"
assert len(recon.get("rejected_fragments", [])) == 8, f"Expected 8 rejected fragments, got {len(recon.get('rejected_fragments', []))}"

# Test download endpoint
recon_id = recon.get("id")
print(f"\n2. Testing GET /api/forensics/reconstructions/{recon_id}/download ...")
down_resp = client.get(f"/api/forensics/reconstructions/{recon_id}/download")
assert down_resp.status_code == 200
raw_bytes = down_resp.content
print(f"Downloaded bytes length: {len(raw_bytes)}")
assert len(raw_bytes) == 43202
assert hashlib.sha256(raw_bytes).hexdigest() == "16d58d65661324944b193a641b6bacf02ab549c4c9e80f234a5ce90de3a48d2b"

# Test image decode
img = Image.open(io.BytesIO(raw_bytes))
img.verify()
img2 = Image.open(io.BytesIO(raw_bytes))
img2.load()
print(f"Successfully decoded image: {img2.width}x{img2.height}, format={img2.format}, mode={img2.mode}")
assert img2.width == 1200 and img2.height == 750

# Check rejected fragments
print("\n3. Sample rejected fragment attribution:")
for rf in recon.get("rejected_fragments", [])[:3]:
    print(f"  - {rf['filename']}: {rf['reason']}")

print("\nALL E2E API FORENSIC TESTS PASSED PERFECTLY!")
