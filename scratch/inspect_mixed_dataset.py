import os
import sys
import glob
import hashlib

# Ensure backend in path
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(script_dir)
backend_dir = os.path.join(project_root, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

os.chdir(backend_dir)

from app.services.jpeg_analysis_service import JPEGAnalysisService

def inspect():
    files = sorted(glob.glob(os.path.join(project_root, "test_dataset", "mixed_dataset", "*.bin")))
    print(f"Total files: {len(files)}")
    for p in files:
        fname = os.path.basename(p)
        with open(p, "rb") as f:
            data = f.read()
        feats = JPEGAnalysisService.extract_features(data)
        markers = [m["name"] for m in feats["markers"]]
        starts_soi = feats["features"]["starts_with_soi"]
        ends_eoi = feats["features"]["ends_with_eoi"]
        cls_name = feats["classification"]
        print(f"{fname:<24} | {len(data):5d} B | {cls_name:<22} | SOI: {str(starts_soi):<5} | EOI: {str(ends_eoi):<5} | Markers: {markers}")

if __name__ == "__main__":
    inspect()
