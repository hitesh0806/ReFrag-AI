import io
import os
import json
import hashlib
from typing import Dict, Any, Tuple, Optional
from PIL import Image
from app.services.jpeg_analysis_service import JPEGAnalysisService, FastJPEGStreamParser

class ValidationService:
    """
    Forensic JPEG Integrity and Multi-Layer Decoder Validation Engine.
    Distinguishes:
    - STRUCTURALLY_PARSEABLE
    - DECODER_VALID
    - RECONSTRUCTION_CONFIRMED

    Enforces strict single-file constraints (disallows internal SOI/EOI, trailing bytes),
    verifies complete MCU entropy bitstream decompression, and performs dev ground-truth
    SHA-256 verification when running benchmark evaluations.
    """

    DEV_GROUND_TRUTH_PATH = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
        "test_dataset",
        "GROUND_TRUTH_DEV_ONLY.json"
    )

    @classmethod
    def get_dev_ground_truth(cls) -> Optional[Dict[str, Any]]:
        """
        Load development ground truth if available in dev environment.
        Strictly for automated test/benchmark verification; never used for reconstruction.
        """
        if os.path.exists(cls.DEV_GROUND_TRUTH_PATH):
            try:
                with open(cls.DEV_GROUND_TRUTH_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return None

    @classmethod
    def validate_jpeg(cls, raw_bytes: bytes) -> Tuple[str, float, Dict[str, Any]]:
        """
        Validate reconstructed JPEG bytes across all forensic axes.
        Returns:
            status: 'VALIDATED' | 'PARTIALLY_VALIDATED' | 'UNCERTAIN' | 'RECONSTRUCTION MISMATCH' | 'INVALID'
            integrity_score: float (0.0 to 1.0)
            validation_result: dict
        """
        reconstructed_size = len(raw_bytes)
        calculated_sha = hashlib.sha256(raw_bytes).hexdigest()

        if reconstructed_size < 4:
            return "INVALID", 0.0, {
                "has_soi": False,
                "has_eoi": False,
                "soi_count": 0,
                "eoi_count": 0,
                "has_internal_soi": False,
                "has_internal_eoi": False,
                "structurally_parseable": False,
                "decoder_valid": False,
                "reconstruction_confirmed": False,
                "reconstructed_size": reconstructed_size,
                "calculated_sha256": calculated_sha,
                "integrity_status": "INVALID",
                "integrity_score": 0.0,
                "failure_reasons": ["Byte sequence too small to contain JPEG markers"],
                "details": "Byte sequence too small to contain JPEG markers",
            }

        has_soi = raw_bytes[:2] == b"\xFF\xD8"
        has_eoi = raw_bytes[-2:] == b"\xFF\xD9"

        soi_count = raw_bytes.count(b"\xFF\xD8")
        eoi_count = raw_bytes.count(b"\xFF\xD9")

        has_internal_soi = soi_count > 1 or (soi_count == 1 and not has_soi)
        has_internal_eoi = eoi_count > 1 or (eoi_count == 1 and not has_eoi)

        failure_reasons = []

        # 1. Structural single-file constraint checks
        if has_internal_soi:
            failure_reasons.append(f"Internal SOI detected: {soi_count} Start-of-Image markers found (multiple JPEGs concatenated)")

        if has_internal_eoi:
            failure_reasons.append(f"Internal EOI detected: {eoi_count} End-of-Image markers found before file termination")

        if not has_soi:
            failure_reasons.append("Missing SOI header (FFD8 at byte 0)")

        if not has_eoi:
            failure_reasons.append("Missing or misaligned EOI terminator (FFD9 at file tail)")

        # 2. Marker structure scan
        markers = JPEGAnalysisService.scan_markers(raw_bytes)
        marker_names = [m["name"] for m in markers]

        has_dqt = "DQT" in marker_names
        has_sof = any(name.startswith("SOF") for name in marker_names)
        has_sos = "SOS" in marker_names
        has_dht = "DHT" in marker_names

        marker_sequence_valid = has_soi and has_eoi and has_sof and has_sos

        # 3. SOF metadata & expected MCU count
        sof_info = JPEGAnalysisService.extract_sof_info(raw_bytes)
        expected_mcus = sof_info.get("expected_mcus", 0) if sof_info else 0

        # 4. Bitstream MCU parsing check via FastJPEGStreamParser
        structurally_parseable = False
        entropy_stream_complete = False
        decoded_mcus = 0
        bitstream_result = "NOT_PARSED"

        if has_soi and has_sos and not has_internal_soi:
            try:
                dht_tables = JPEGAnalysisService.extract_dht_tables(raw_bytes)
                if dht_tables:
                    sos_idx = raw_bytes.find(b"\xFF\xDA")
                    if sos_idx != -1 and sos_idx + 4 < len(raw_bytes):
                        sos_len = (raw_bytes[sos_idx + 2] << 8) | raw_bytes[sos_idx + 3]
                        start_offset = sos_idx + 2 + sos_len
                        parser = FastJPEGStreamParser(dht_tables)
                        decoded_mcus, bitstream_result = parser.feed(raw_bytes, is_first=True, start_offset=start_offset)
                        
                        if expected_mcus > 0:
                            if decoded_mcus >= expected_mcus and "OVERFLOW" not in bitstream_result and "INVALID" not in bitstream_result:
                                entropy_stream_complete = True
                                structurally_parseable = True
                            elif decoded_mcus < expected_mcus:
                                failure_reasons.append(f"Incomplete entropy scan: Decoded {decoded_mcus} of {expected_mcus} MCUs ({bitstream_result})")
                        else:
                            if "OVERFLOW" not in bitstream_result and "INVALID" not in bitstream_result:
                                structurally_parseable = True
            except Exception as e:
                bitstream_result = f"ERROR: {str(e)[:50]}"

        # 5. Full raster decompression validation via Pillow
        decoder_valid = False
        image_metadata = {}
        decoder_error = None

        if has_soi and not has_internal_soi:
            try:
                bio1 = io.BytesIO(raw_bytes)
                img1 = Image.open(bio1)
                img1.verify()

                bio2 = io.BytesIO(raw_bytes)
                img2 = Image.open(bio2)
                img2.load()

                decoder_valid = True
                image_metadata = {
                    "width": img2.width,
                    "height": img2.height,
                    "format": img2.format or "JPEG",
                    "mode": img2.mode,
                }
            except Exception as e:
                decoder_error = str(e)
                failure_reasons.append(f"Image decoder raster decompression error: {decoder_error}")

        # 6. Check development ground truth (dev benchmark verification)
        dev_gt = cls.get_dev_ground_truth()
        dev_verification = "NOT_AVAILABLE"
        target_sha256 = None
        exact_sha_match = None

        if dev_gt:
            target_sha256 = dev_gt.get("target_sha256")
            if target_sha256:
                if calculated_sha.lower() == target_sha256.lower():
                    dev_verification = "PASS"
                    exact_sha_match = True
                else:
                    dev_verification = "FAIL"
                    exact_sha_match = False
                    failure_reasons.append(f"SHA-256 mismatch against target ground truth (reconstructed: {calculated_sha[:12]}..., expected: {target_sha256[:12]}...)")

        # 7. Synthesize Reconstruction Status
        # Requirements:
        # VALIDATED: Passes all structural, marker, bitstream, decoder checks and exact dev SHA256 (if available)
        # RECONSTRUCTION MISMATCH: Decoder or fragments assembled but fails dev SHA256 ground truth
        # PARTIALLY_VALIDATED: Decodes with minor structural discrepancies or incomplete MCUs
        # UNCERTAIN: Incomplete scan data or unverified decoder state
        # INVALID: Severe internal SOI/EOI, broken markers, or decode failure

        if has_internal_soi or has_internal_eoi:
            status = "INVALID"
            integrity_score = 0.05
            reconstruction_confirmed = False
            details = "Reconstruction rejected: Multiple JPEGs concatenated into candidate stream."
        elif dev_verification == "FAIL":
            status = "RECONSTRUCTION MISMATCH"
            integrity_score = 0.40
            reconstruction_confirmed = False
            details = "Reconstruction mismatch: Fragment sequence does not match target original ground truth."
        elif dev_verification == "PASS":
            status = "VALIDATED"
            integrity_score = 1.0
            reconstruction_confirmed = True
            details = f"Reconstructed JPEG verified and byte-for-byte confirmed ({image_metadata.get('width', 0)}x{image_metadata.get('height', 0)} {image_metadata.get('mode', '')})."
        elif structurally_parseable and decoder_valid and marker_sequence_valid:
            status = "VALIDATED"
            integrity_score = 0.98
            reconstruction_confirmed = True
            details = f"Reconstruction verified: 100% MCUs decoded and image decompresses cleanly ({image_metadata.get('width', 0)}x{image_metadata.get('height', 0)})."
        elif decoder_valid and has_soi and has_eoi:
            status = "PARTIALLY_VALIDATED"
            integrity_score = 0.70
            reconstruction_confirmed = False
            details = f"Decodes with caveats: {'; '.join(failure_reasons) if failure_reasons else 'Minor non-fatal bitstream irregularities'}"
        elif decoder_valid:
            status = "UNCERTAIN"
            integrity_score = 0.45
            reconstruction_confirmed = False
            details = "Decoder produced raster but structural integrity is uncertain."
        else:
            status = "INVALID"
            integrity_score = 0.10
            reconstruction_confirmed = False
            details = f"Validation failed: {'; '.join(failure_reasons) if failure_reasons else 'Decompression error'}"

        validation_result = {
            "integrity_status": status,
            "integrity_score": integrity_score,
            "reconstruction_confirmed": reconstruction_confirmed,
            "structurally_parseable": structurally_parseable,
            "decoder_valid": decoder_valid,
            "decoder_validation": decoder_valid,
            "has_soi": has_soi,
            "has_eoi": has_eoi,
            "soi_count": soi_count,
            "eoi_count": eoi_count,
            "has_internal_soi": has_internal_soi,
            "has_internal_eoi": has_internal_eoi,
            "has_dqt": has_dqt,
            "has_sof": has_sof,
            "has_sos": has_sos,
            "has_dht": has_dht,
            "marker_sequence_valid": marker_sequence_valid,
            "expected_mcus": expected_mcus,
            "decoded_mcus": decoded_mcus,
            "mcu_completion_rate": round(decoded_mcus / expected_mcus, 4) if expected_mcus > 0 else 1.0,
            "entropy_stream_complete": entropy_stream_complete,
            "bitstream_result": bitstream_result,
            "reconstructed_size": reconstructed_size,
            "calculated_sha256": calculated_sha,
            "dev_verification": dev_verification,
            "target_sha256": target_sha256,
            "exact_sha_match": exact_sha_match,
            "image_metadata": image_metadata,
            "failure_reasons": failure_reasons,
            "details": details,
            "detected_markers": marker_names,
        }

        return status, integrity_score, validation_result

