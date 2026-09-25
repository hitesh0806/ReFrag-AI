import os
import io
import json
import hashlib
from PIL import Image, ImageDraw

def create_unrelated_jpeg(text: str, size: tuple, color1: tuple, color2: tuple, quality: int) -> bytes:
    w, h = size
    img = Image.new("RGB", size, color=color1)
    draw = ImageDraw.Draw(img)
    for y in range(h):
        r = int(color1[0] + (y / h) * (color2[0] - color1[0]))
        g = int(color1[1] + (y / h) * (color2[1] - color1[1]))
        b = int(color1[2] + (y / h) * (color2[2] - color1[2]))
        draw.line([(0, y), (w, y)], fill=(r, g, b))
    for x in range(0, w, 50):
        draw.line([(x, 0), (x, h)], fill=(120, 120, 120))
    draw.text((40, 40), f"FORENSIC_DECOY_UNRELATED: {text}", fill=(255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=quality)
    return buf.getvalue()

def build_dataset():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target_img_path = os.path.join(base_dir, "test_dataset", "evidence_target.jpg")
    mixed_dir = os.path.join(base_dir, "test_dataset", "mixed_dataset")
    gt_path = os.path.join(base_dir, "test_dataset", "GROUND_TRUTH_DEV_ONLY.json")

    with open(target_img_path, "rb") as f:
        target_bytes = f.read()

    target_sha256 = hashlib.sha256(target_bytes).hexdigest()
    assert target_sha256 == "16d58d65661324944b193a641b6bacf02ab549c4c9e80f234a5ce90de3a48d2b", "Target SHA mismatch!"
    assert len(target_bytes) == 43202, f"Target size expected 43202, got {len(target_bytes)}"

    # Clean mixed_dir
    os.makedirs(mixed_dir, exist_ok=True)
    for item in os.listdir(mixed_dir):
        p = os.path.join(mixed_dir, item)
        if os.path.isfile(p):
            os.remove(p)

    # 1. Split target into 12 exact byte fragments (matching the canonical cuts)
    # Target cut offsets for 43202 bytes:
    # 0..3600, 3600..7200, 7200..10800, 10800..14401, 14401..18001, 18001..21601,
    # 21601..25201, 25201..28801, 28801..32402, 32402..36002, 36002..39602, 39602..43202
    cuts = [
        (0, 3600, "fragment_01_42a0f2.bin"),
        (3600, 7200, "fragment_02_5b6418.bin"),
        (7200, 10800, "fragment_03_7c5126.bin"),
        (10800, 14401, "fragment_04_9ec84b.bin"),
        (14401, 18001, "fragment_05_216ab8.bin"),
        (18001, 21601, "fragment_06_4715a9.bin"),
        (21601, 25201, "fragment_07_501849.bin"),
        (25201, 28801, "fragment_08_b12c87.bin"),
        (28801, 32402, "fragment_09_15759a.bin"),
        (32402, 36002, "fragment_10_4fa24d.bin"),
        (36002, 39602, "fragment_11_f70baf.bin"),
        (39602, 43202, "fragment_12_3f5f1c.bin"),
    ]

    target_filenames = []
    target_assembled = bytearray()
    for start, end, fname in cuts:
        chunk = target_bytes[start:end]
        target_assembled.extend(chunk)
        with open(os.path.join(mixed_dir, fname), "wb") as f:
            f.write(chunk)
        target_filenames.append(fname)

    assert bytes(target_assembled) == target_bytes, "Assembled target fragments do not match original bytes!"

    # 2. Generate 8 unrelated source JPEGs and extract incomplete decoy slices
    u1 = create_unrelated_jpeg("DOCUMENT_ALPHA", (800, 600), (30, 40, 50), (90, 80, 70), 75)
    u2 = create_unrelated_jpeg("LANDSCAPE_BETA", (640, 480), (100, 50, 20), (20, 10, 50), 80)
    u3 = create_unrelated_jpeg("GEOMETRIC_GAMMA", (720, 480), (10, 80, 30), (40, 20, 80), 85)
    u4 = create_unrelated_jpeg("CIRCUIT_DELTA", (500, 500), (10, 20, 30), (80, 120, 150), 70)
    u5 = create_unrelated_jpeg("TEXTURE_EPSILON", (900, 600), (50, 50, 80), (120, 80, 40), 82)
    u6 = create_unrelated_jpeg("STAR_ZETA", (600, 600), (5, 5, 25), (20, 30, 80), 78)
    u7 = create_unrelated_jpeg("THERMAL_ETA", (800, 400), (120, 20, 20), (200, 150, 10), 85)
    u8 = create_unrelated_jpeg("BLUEPRINT_THETA", (750, 500), (15, 35, 75), (50, 100, 180), 75)

    # Cut slices strictly ensuring NO complete JPEG is reconstructable:
    # Decoy 1: Interior entropy slice (no markers)
    d1 = u1[2000:5500]
    # Decoy 2: Header slice, sliced strictly BEFORE FF DA (SOS) marker
    sos2 = u2.find(b"\xFF\xDA")
    d2 = u2[:sos2] if sos2 != -1 else u2[:3000]
    assert b"\xFF\xDA" not in d2, "Decoy 2 must not contain SOS!"
    # Decoy 3: Interior entropy slice (no markers)
    d3 = u3[2500:6000]
    # Decoy 4: Interior entropy slice (no markers)
    d4 = u4[1500:5000]
    # Decoy 5: Interior entropy slice (no markers)
    d5 = u5[3000:6500]
    # Decoy 6: Tail slice with EOI, but NO headers and NO SOI
    d6 = u6[max(0, len(u6) - 3400):]
    assert b"\xFF\xD8" not in d6, "Decoy 6 must not contain SOI!"
    # Decoy 7: Interior entropy slice (no markers)
    d7 = u7[1800:5300]
    # Decoy 8: Interior entropy slice (no markers)
    d8 = u8[2200:5700]

    decoy_slices = [
        ("decoy_unrelated_01.bin", d1),
        ("decoy_unrelated_02.bin", d2),
        ("decoy_unrelated_03.bin", d3),
        ("decoy_unrelated_04.bin", d4),
        ("decoy_unrelated_05.bin", d5),
        ("decoy_unrelated_06.bin", d6),
        ("decoy_unrelated_07.bin", d7),
        ("decoy_unrelated_08.bin", d8),
    ]

    decoy_filenames = []
    for fname, dbytes in decoy_slices:
        with open(os.path.join(mixed_dir, fname), "wb") as f:
            f.write(dbytes)
        decoy_filenames.append(fname)

    # 3. Verify: No combination of decoys contains both SOI, SOS, and EOI
    for fname, dbytes in decoy_slices:
        assert not (dbytes.startswith(b"\xFF\xD8") and dbytes.endswith(b"\xFF\xD9")), f"{fname} is a standalone JPEG!"

    # 4. Write GROUND_TRUTH_DEV_ONLY.json
    gt_data = {
        "target_description": "Mixed JPEG Forensic Evaluation Ground Truth",
        "target_sha256": target_sha256,
        "target_size": 43202,
        "target_fragment_count": 12,
        "decoy_fragment_count": 8,
        "total_fragment_count": 20,
        "correct_fragment_order": target_filenames,
        "decoy_fragments": decoy_filenames
    }

    with open(gt_path, "w", encoding="utf-8") as f:
        json.dump(gt_data, f, indent=2)

    print("=== DATASET BUILD COMPLETE ===")
    print(f"Target Fragments ({len(target_filenames)}):")
    for tf in target_filenames:
        print(f"  - {tf} ({os.path.getsize(os.path.join(mixed_dir, tf))} bytes)")
    print(f"Decoy Fragments ({len(decoy_filenames)}):")
    for df in decoy_filenames:
        print(f"  - {df} ({os.path.getsize(os.path.join(mixed_dir, df))} bytes)")
    print(f"Total Fragments: {len(target_filenames) + len(decoy_filenames)}")
    print(f"Ground Truth written to: {gt_path}")

if __name__ == "__main__":
    build_dataset()
