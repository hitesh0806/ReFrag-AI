import os
import sys
import io
import json
import random
import hashlib
import argparse
from typing import List, Dict, Any, Tuple, Optional
from PIL import Image, ImageDraw, ImageFont

def generate_sample_jpeg(output_path: str, width: int = 800, height: int = 600) -> str:
    """
    Generate a rich test JPEG with geometric patterns, color gradients, and text.
    """
    img = Image.new("RGB", (width, height), color=(20, 24, 38))
    draw = ImageDraw.Draw(img)

    # Background gradient
    for y in range(height):
        r = int(20 + (y / height) * 60)
        g = int(24 + (y / height) * 40)
        b = int(38 + (y / height) * 120)
        draw.line([(0, y), (width, y)], fill=(r, g, b))

    # Concentric forensic target rings
    center_x, center_y = width // 2, height // 2
    for radius in range(250, 20, -30):
        color = (
            (radius * 3) % 255,
            (radius * 7) % 255,
            (radius * 11) % 255
        )
        draw.ellipse(
            [center_x - radius, center_y - radius, center_x + radius, center_y + radius],
            outline=color,
            width=3
        )

    # Forensic Grid Lines
    for x in range(0, width, 50):
        draw.line([(x, 0), (x, height)], fill=(40, 50, 80), width=1)
    for y in range(0, height, 50):
        draw.line([(0, y), (width, y)], fill=(40, 50, 80), width=1)

    # Forensic Labels
    draw.rectangle([60, 50, width - 60, 140], fill=(15, 20, 35), outline=(124, 92, 255), width=2)
    draw.text((80, 65), "REFRAG AI - FORENSIC RECONSTRUCTION TEST TARGET", fill=(255, 255, 255))
    draw.text((80, 95), "Classification: EVIDENCE BENCHMARK // SHA-256 INTEGRITY VALIDATION", fill=(160, 175, 205))

    # Diagonal calibration line
    draw.line([(0, 0), (width, height)], fill=(255, 75, 75), width=2)
    draw.line([(0, height), (width, 0)], fill=(75, 255, 125), width=2)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    img.save(output_path, "JPEG", quality=90, restart_marker_blocks=16)
    print(f"[+] Generated synthetic test JPEG: {output_path} ({os.path.getsize(output_path)} bytes)")
    return output_path

def split_and_shuffle_jpeg(
    jpeg_path: str,
    output_dir: str,
    num_fragments: int = 8,
    randomize_sizes: bool = True
) -> Dict[str, Any]:
    """
    Split a JPEG into raw byte fragments, shuffle them, assign random meaningless names,
    and output a ground-truth manifest outside the fragments directory.
    """
    with open(jpeg_path, "rb") as f:
        full_bytes = f.read()

    total_len = len(full_bytes)
    original_sha256 = hashlib.sha256(full_bytes).hexdigest()

    if num_fragments < 2:
        num_fragments = 2

    # Calculate split cutpoints
    if randomize_sizes:
        # Generate random cut points ensuring each fragment has a reasonable minimum size
        min_frag_size = max(64, total_len // (num_fragments * 4))
        cuts = sorted(random.sample(range(min_frag_size, total_len - min_frag_size), num_fragments - 1))
        cutpoints = [0] + cuts + [total_len]
    else:
        # Uniform chunk sizes
        chunk_size = total_len // num_fragments
        cutpoints = [i * chunk_size for i in range(num_fragments)] + [total_len]

    # Slice raw byte fragments in original sequence
    ordered_fragments = []
    for i in range(num_fragments):
        start = cutpoints[i]
        end = cutpoints[i + 1]
        frag_bytes = full_bytes[start:end]
        frag_hash = hashlib.sha256(frag_bytes).hexdigest()

        # Generate a meaningless, non-sequential filename
        rand_token = hashlib.sha256(f"{i}_{frag_hash}_{random.random()}".encode()).hexdigest()[:8]
        rand_filename = f"fragment_{rand_token}.bin"

        ordered_fragments.append({
            "original_order_index": i,
            "start_offset": start,
            "end_offset": end,
            "size": len(frag_bytes),
            "sha256": frag_hash,
            "assigned_filename": rand_filename,
            "bytes": frag_bytes,
        })

    # Prepare output directories
    # The fragments folder will ONLY contain shuffled, randomly named binary fragments
    fragments_dir = os.path.join(output_dir, "shuffled_fragments")
    os.makedirs(fragments_dir, exist_ok=True)

    # Clean existing fragments in target directory
    for item in os.listdir(fragments_dir):
        p = os.path.join(fragments_dir, item)
        if os.path.isfile(p):
            os.remove(p)

    # Shuffle the fragments
    shuffled_fragments = list(ordered_fragments)
    random.shuffle(shuffled_fragments)

    # Write out each shuffled fragment with exact bytes
    for frag in shuffled_fragments:
        frag_path = os.path.join(fragments_dir, frag["assigned_filename"])
        with open(frag_path, "wb") as f:
            f.write(frag["bytes"])

    # Create Ground Truth Manifest OUTSIDE the fragments folder
    manifest = {
        "benchmark_info": {
            "source_jpeg": os.path.abspath(jpeg_path),
            "original_size": total_len,
            "original_sha256": original_sha256,
            "num_fragments": num_fragments,
        },
        "ground_truth_order": [
            {
                "sequence_step": f["original_order_index"] + 1,
                "assigned_filename": f["assigned_filename"],
                "sha256": f["sha256"],
                "start_offset": f["start_offset"],
                "end_offset": f["end_offset"],
                "size": f["size"],
            }
            for f in ordered_fragments
        ],
        "shuffled_manifest": [
            {
                "filename": f["assigned_filename"],
                "sha256": f["sha256"],
                "size": f["size"],
            }
            for f in shuffled_fragments
        ]
    }

    manifest_path = os.path.join(output_dir, "ground_truth_manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"\n=======================================================")
    print(f"      JPEG FRAGMENT BENCHMARK GENERATION COMPLETE       ")
    print(f"=======================================================")
    print(f"  • Source JPEG          : {jpeg_path} ({total_len} bytes)")
    print(f"  • Original SHA-256     : {original_sha256}")
    print(f"  • Fragments Created    : {num_fragments} fragments")
    print(f"  • Output Directory     : {fragments_dir}")
    print(f"  • Ground Truth Manifest: {manifest_path} (DO NOT UPLOAD)")
    print(f"-------------------------------------------------------")
    for f in ordered_fragments:
        print(f"    [{f['original_order_index'] + 1}/{num_fragments}] -> {f['assigned_filename']} ({f['size']} bytes, offset {f['start_offset']}..{f['end_offset']})")
    print(f"=======================================================\n")

    return manifest

def evaluate_reconstruction(
    manifest_path: str,
    reconstructed_order_filenames: List[str],
    reconstructed_bytes: Optional[bytes] = None
) -> Dict[str, Any]:
    """
    Forensic evaluation metrics comparing candidate reconstruction to ground truth:
    - Fragment ordering accuracy (correct adjacent pairs / total adjacent pairs)
    - Fragment placement accuracy (correct position / total fragments)
    - Byte-level accuracy (correct contiguous bytes / original total bytes)
    - Reconstruction success (decoder verification)
    """
    with open(manifest_path, "r") as f:
        manifest = json.load(f)

    gt_order = [item["assigned_filename"] for item in manifest["ground_truth_order"]]
    n = len(gt_order)

    # 1. Fragment placement accuracy
    correct_positions = 0
    for idx, fname in enumerate(reconstructed_order_filenames):
        if idx < n and fname == gt_order[idx]:
            correct_positions += 1
    placement_accuracy = round(correct_positions / n, 4) if n > 0 else 0.0

    # 2. Adjacent pair ordering accuracy
    gt_pairs = set((gt_order[i], gt_order[i + 1]) for i in range(n - 1))
    recon_pairs = [
        (reconstructed_order_filenames[i], reconstructed_order_filenames[i + 1])
        for i in range(len(reconstructed_order_filenames) - 1)
    ]
    correct_pairs = sum(1 for p in recon_pairs if p in gt_pairs)
    total_pairs = max(1, n - 1)
    ordering_accuracy = round(correct_pairs / total_pairs, 4)

    # 3. Decoder verification & byte accuracy
    decoder_valid = False
    byte_accuracy = 0.0

    if reconstructed_bytes:
        source_path = manifest["benchmark_info"]["source_jpeg"]
        with open(source_path, "rb") as f:
            original_bytes = f.read()

        recon_hash = hashlib.sha256(reconstructed_bytes).hexdigest()
        byte_match = (recon_hash == manifest["benchmark_info"]["original_sha256"])
        byte_accuracy = 1.0 if byte_match else round(min(len(reconstructed_bytes), len(original_bytes)) / max(len(original_bytes), 1), 4)

        try:
            img = Image.open(io.BytesIO(reconstructed_bytes))
            img.verify()
            img2 = Image.open(io.BytesIO(reconstructed_bytes))
            img2.load()
            decoder_valid = True
        except Exception:
            decoder_valid = False

    metrics = {
        "total_fragments": n,
        "placement_accuracy": placement_accuracy,
        "ordering_accuracy": ordering_accuracy,
        "correct_adjacent_pairs": f"{correct_pairs}/{total_pairs}",
        "byte_level_accuracy": byte_accuracy,
        "decoder_validation_success": decoder_valid,
    }

    print("\n--- FORENSIC RECONSTRUCTION EVALUATION ---")
    print(f"  • Fragment Placement Accuracy: {placement_accuracy * 100:.1f}%")
    print(f"  • Adjacent Pair Accuracy     : {ordering_accuracy * 100:.1f}% ({correct_pairs}/{total_pairs} pairs)")
    print(f"  • Byte-Level Match Accuracy  : {byte_accuracy * 100:.1f}%")
    print(f"  • Image Decoder Success      : {'PASS' if decoder_valid else 'FAIL'}")
    print("-------------------------------------------\n")

    return metrics

def main():
    parser = argparse.ArgumentParser(description="ReFrag AI - Shuffled JPEG Fragment Dataset Generator")
    parser.add_argument("--input", "-i", type=str, default=None, help="Input valid JPEG path. If omitted, generates synthetic JPEG.")
    parser.add_argument("--output-dir", "-o", type=str, default="./test_dataset", help="Output directory for shuffled fragments.")
    parser.add_argument("--num-fragments", "-n", type=int, default=8, help="Number of fragments to split into (e.g. 5-20).")
    parser.add_argument("--uniform", action="store_true", help="Use uniform chunk sizes instead of varied sizes.")

    args = parser.parse_args()

    jpeg_path = args.input
    if not jpeg_path or not os.path.exists(jpeg_path):
        sample_path = os.path.join(args.output_dir, "reference_image.jpg")
        jpeg_path = generate_sample_jpeg(sample_path)

    split_and_shuffle_jpeg(
        jpeg_path=jpeg_path,
        output_dir=args.output_dir,
        num_fragments=args.num_fragments,
        randomize_sizes=not args.uniform
    )

if __name__ == "__main__":
    main()
