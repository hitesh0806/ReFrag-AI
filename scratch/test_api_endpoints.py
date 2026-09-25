import os
import glob
import httpx

API_BASE = "http://localhost:8000/api/forensics"

def test_full_api_flow():
    client = httpx.Client(timeout=30.0)

    # Health check
    res = client.get("http://localhost:8000/")
    print(f"Health Check: {res.status_code} -> {res.json()}")
    assert res.status_code == 200

    # Step 1: Upload shuffled fragments
    frag_files = glob.glob("test_dataset/shuffled_fragments/*.bin")
    print(f"Uploading {len(frag_files)} shuffled fragments via HTTP POST /upload...")

    files_payload = []
    rel_paths = []
    for p in frag_files:
        fname = os.path.basename(p)
        with open(p, "rb") as fh:
            content = fh.read()
        files_payload.append(("files", (fname, content, "application/octet-stream")))
        rel_paths.append(f"shuffled_dataset/{fname}")

    data_payload = {
        "case_name": "Automated HTTP Benchmark Ingestion",
        "relative_paths": rel_paths,
    }

    upload_res = client.post(f"{API_BASE}/upload", files=files_payload, data=data_payload)

    print(f"Upload Status: {upload_res.status_code}")
    assert upload_res.status_code == 201
    upload_data = upload_res.json()
    case_id = upload_data["case_id"]
    print(f"  -> Ingested Case ID: {case_id}")
    print(f"  -> Files uploaded: {upload_data['files_uploaded']}")

    # Step 2: Analyze Fragments
    print(f"\nTriggering Analysis: POST /cases/{case_id}/analyze...")
    analyze_res = client.post(f"{API_BASE}/cases/{case_id}/analyze")
    print(f"Analyze Status: {analyze_res.status_code}")
    assert analyze_res.status_code == 200
    analysis_data = analyze_res.json()
    print(f"  -> Total fragments analyzed: {analysis_data['total_fragments']}")
    print(f"  -> Total relationships built: {analysis_data['total_relationships']}")

    # Step 3: Query Fragments
    frags_res = client.get(f"{API_BASE}/cases/{case_id}/fragments")
    assert frags_res.status_code == 200
    frags_list = frags_res.json()
    print(f"GET /cases/{case_id}/fragments -> Retrieved {len(frags_list)} fragments")
    for f in frags_list:
        print(f"    [{f['id'][:8]}] {f['source_filename']}: {f['classification']} (entropy: {f['entropy']})")

    # Step 4: Query Relationships
    rels_res = client.get(f"{API_BASE}/cases/{case_id}/relationships")
    assert rels_res.status_code == 200
    rels_list = rels_res.json()
    print(f"GET /cases/{case_id}/relationships -> Retrieved {len(rels_list)} relationships")
    top_rel = rels_list[0]
    print(f"  Top Relationship: {top_rel['from_filename']} -> {top_rel['to_filename']} ({top_rel['total_score'] * 100:.1f}%)")

    # Step 5: Reconstruct JPEG
    print(f"\nTriggering Reconstruction: POST /cases/{case_id}/reconstruct...")
    recon_res = client.post(f"{API_BASE}/cases/{case_id}/reconstruct")
    print(f"Reconstruct Status: {recon_res.status_code}")
    assert recon_res.status_code == 200
    recon_list = recon_res.json()
    assert len(recon_list) > 0
    recon = recon_list[0]
    recon_id = recon["id"]
    print(f"  -> Candidate ID: {recon_id}")
    print(f"  -> Status: {recon['status']}")
    print(f"  -> Confidence: {recon['confidence'] * 100:.1f}%")
    print(f"  -> Integrity Score: {recon['integrity_score'] * 100:.1f}%")
    print(f"  -> Inferred Order: {len(recon['fragment_order'])} fragments")

    # Step 6: Test View Endpoint
    view_res = client.get(f"{API_BASE}/reconstructions/{recon_id}/view")
    print(f"GET /reconstructions/{recon_id}/view -> Status: {view_res.status_code}, Content-Type: {view_res.headers.get('content-type')}, Bytes: {len(view_res.content)}")
    assert view_res.status_code == 200
    assert view_res.headers.get("content-type") == "image/jpeg"

    # Step 7: Test Download Endpoint
    dl_res = client.get(f"{API_BASE}/reconstructions/{recon_id}/download")
    print(f"GET /reconstructions/{recon_id}/download -> Status: {dl_res.status_code}, Disposition: {dl_res.headers.get('content-disposition')}, Bytes: {len(dl_res.content)}")
    assert dl_res.status_code == 200
    assert dl_res.content[:2] == b"\xFF\xD8"
    assert dl_res.content[-2:] == b"\xFF\xD9"

    print("\n==========================================")
    print(" ALL HTTP FORENSIC API ENDPOINTS PASSED! ")
    print("==========================================")

if __name__ == "__main__":
    test_full_api_flow()
