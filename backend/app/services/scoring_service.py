import io
from typing import Dict, Any, Optional, List, Tuple
from PIL import Image
from app.services.jpeg_analysis_service import JPEGAnalysisService, JPEG_MARKER_NAMES

class ScoringService:
    """
    Forensic Pairwise Compatibility Scoring Engine.
    Evaluates directed candidate relationship A -> B across multiple forensic evidence axes:
    - Physical / positional evidence
    - JPEG structural progression evidence
    - Boundary byte transition & marker seam evidence
    - Incremental parser validation evidence
    - ML adjacency model score (interface ready, set to None for now)
    """

    # Configurable base weights for available evidence sources
    DEFAULT_WEIGHTS = {
        "structural": 0.35,
        "boundary": 0.35,
        "parser": 0.30,
        "physical": 0.20,
        "ml": 0.20,
    }

    @classmethod
    def evaluate_physical_score(
        cls,
        from_frag: Dict[str, Any],
        to_frag: Dict[str, Any]
    ) -> Tuple[Optional[float], Optional[str]]:
        """
        Physical/positional evidence score.
        If LBA / disk offsets are not recorded, returns (None, 'Unavailable').
        """
        start_a = from_frag.get("start_offset")
        end_a = from_frag.get("end_offset")
        start_b = to_frag.get("start_offset")

        if start_a is None or end_a is None or start_b is None:
            return None, "Physical storage offset / LBA metadata unavailable"

        if end_a == start_b:
            return 1.0, f"Contiguous physical sector alignment ({end_a} == {start_b})"
        elif start_b > start_a:
            # Monotonically increasing storage order
            dist = start_b - end_a
            score = max(0.1, 1.0 / (1.0 + (dist / 4096.0)))
            return round(score, 3), f"Forward storage offset proximity (delta: {dist} bytes)"
        else:
            return 0.05, f"Reverse storage offset order ({start_b} < {start_a})"

    @classmethod
    def evaluate_structural_score(
        cls,
        feat_a: Dict[str, Any],
        feat_b: Dict[str, Any]
    ) -> Tuple[float, List[str]]:
        """
        Determine whether A -> B follows valid JPEG structural marker and section progression.
        """
        explanations = []

        class_a = feat_a.get("classification", "UNKNOWN_JPEG_FRAGMENT")
        class_b = feat_b.get("classification", "UNKNOWN_JPEG_FRAGMENT")

        ends_eoi_a = feat_a.get("ends_with_eoi", False)
        starts_soi_b = feat_b.get("starts_with_soi", False)
        starts_soi_a = feat_a.get("starts_with_soi", False)
        ends_eoi_b = feat_b.get("ends_with_eoi", False)
        contains_sos_a = feat_a.get("contains_sos", False)
        contains_sos_b = feat_b.get("contains_sos", False)

        # Severe structural violations
        if ends_eoi_a:
            explanations.append("Severe penalty: Preceding fragment A already terminates the JPEG with EOI (FFD9)")
            return 0.001, explanations

        if starts_soi_b:
            explanations.append("Severe penalty: Target fragment B starts with SOI (FFD8); cannot be preceded by another fragment")
            return 0.001, explanations

        if starts_soi_a and starts_soi_b:
            explanations.append("Severe penalty: Multiple start-of-image headers")
            return 0.001, explanations

        # Canonical progression evaluation
        score = 0.50  # Neutral baseline

        # 1. Header leading into Structural or Metadata
        if class_a == "HEADER_FRAGMENT":
            if class_b in ("METADATA_FRAGMENT", "STRUCTURAL_FRAGMENT"):
                score = 0.94
                explanations.append("Canonical progression: JPEG header followed by metadata/structural tables")
            elif class_b == "ENTROPY_DATA_FRAGMENT":
                if contains_sos_a:
                    score = 0.96
                    explanations.append("Canonical progression: Fragment A ends with SOS and is directly followed by scan data")
                else:
                    score = 0.70
                    explanations.append("Plausible progression: Fragment A leads into scan data")
            elif class_b == "ENDING_FRAGMENT":
                score = 0.40
                explanations.append("Direct transition from header to ending fragment (tiny image or missing intermediate scan data)")

        # 2. Structural leading into Structural or Entropy Data
        elif class_a == "STRUCTURAL_FRAGMENT":
            if contains_sos_a:
                if class_b in ("ENTROPY_DATA_FRAGMENT", "ENDING_FRAGMENT"):
                    score = 0.95
                    explanations.append("Canonical progression: SOS scan header in A followed by entropy stream in B")
                else:
                    score = 0.30
                    explanations.append("Unlikely: Non-entropy fragment following SOS header")
            elif class_b == "STRUCTURAL_FRAGMENT":
                score = 0.88
                explanations.append("Coherent structural table progression (DQT/DHT/SOF)")
            elif class_b == "ENTROPY_DATA_FRAGMENT":
                score = 0.85
                explanations.append("Structural tables transitioning to compressed entropy data")

        # 3. Entropy Data to Entropy Data
        elif class_a == "ENTROPY_DATA_FRAGMENT":
            if class_b == "ENTROPY_DATA_FRAGMENT":
                score = 0.88
                explanations.append("Coherent continuation of compressed entropy scan data stream")
            elif class_b == "ENDING_FRAGMENT":
                score = 0.82
                explanations.append("Compressed entropy stream leading into candidate EOI ending fragment")
            elif class_b in ("HEADER_FRAGMENT", "METADATA_FRAGMENT"):
                score = 0.05
                explanations.append("Severe penalty: Header/Metadata cannot follow compressed entropy data in baseline JPEG")

        # 4. Fine-grained JPEG Restart Marker (RST0..RST7) progression
        markers_a = [m for m in feat_a.get("marker_sequence", []) if m.startswith("RST")]
        markers_b = [m for m in feat_b.get("marker_sequence", []) if m.startswith("RST")]

        if contains_sos_a and markers_b and markers_b[0] == "RST0":
            score = max(score, 0.99)
            explanations.append("Canonical progression: Scan header SOS in A initiates stream leading to first restart marker RST0 in B")

        if markers_a and markers_b:
            last_rst_a = int(markers_a[-1][3:])
            first_rst_b = int(markers_b[0][3:])
            expected_rst_b = (last_rst_a + 1) % 8
            if first_rst_b == expected_rst_b:
                score = max(score, 0.99)
                explanations.append(f"Canonical restart marker progression: RST{last_rst_a} in A followed immediately by expected RST{first_rst_b} in B")
            elif (first_rst_b - last_rst_a) % 8 in (2, 3):
                score = max(score, 0.75)
                explanations.append(f"Forward restart marker interval progression (RST{last_rst_a} -> RST{first_rst_b})")
            else:
                score = min(score, 0.05)
                explanations.append(f"Incompatible restart marker sequence: RST{last_rst_a} followed by unexpected RST{first_rst_b}")

        return round(score, 3), explanations

    @staticmethod
    def get_periodic_pattern(data: bytes, from_head: bool = True, max_len: int = 32) -> Tuple[Optional[bytes], int]:
        """
        Extract the minimal repeating unit (fundamental period) at the head or tail of a byte slice.
        """
        chunk = data[:max_len] if from_head else data[-max_len:]
        if len(chunk) < 4:
            return None, 0
        for plen in (2, 3, 4, 8):
            if from_head:
                pat = chunk[:plen]
                reps = 0
                idx = 0
                while idx + plen <= len(chunk) and chunk[idx:idx + plen] == pat:
                    reps += 1
                    idx += plen
                if reps >= 2:
                    for sub_len in (2, 3, 4):
                        if sub_len < plen and plen % sub_len == 0:
                            sub_pat = pat[:sub_len]
                            if sub_pat * (plen // sub_len) == pat:
                                return sub_pat, reps * (plen // sub_len)
                    return pat, reps
            else:
                pat = chunk[-plen:]
                reps = 0
                idx = len(chunk)
                while idx >= plen and chunk[idx - plen:idx] == pat:
                    reps += 1
                    idx -= plen
                if reps >= 2:
                    for sub_len in (2, 3, 4):
                        if sub_len < plen and plen % sub_len == 0:
                            sub_pat = pat[-sub_len:]
                            if sub_pat * (plen // sub_len) == pat:
                                return sub_pat, reps * (plen // sub_len)
                    return pat, reps
        return None, 0

    @classmethod
    def evaluate_boundary_score(
        cls,
        raw_a: bytes,
        raw_b: bytes
    ) -> Tuple[float, List[str]]:
        """
        Analyze the exact boundary seam: tail of A and head of B.
        Checks for split JPEG markers, byte-stuffing continuity, periodic macroblock patterns,
        illegal marker sequences, and boundary entropy smoothness.
        """
        explanations = []

        if not raw_a or not raw_b:
            return 0.5, ["Empty boundary byte sequence"]

        tail_a = raw_a[-32:] if len(raw_a) >= 32 else raw_a
        head_b = raw_b[:32] if len(raw_b) >= 32 else raw_b
        seam_32 = tail_a[-16:] + head_b[:16]

        score = 0.70  # Baseline seam score

        # 1. Periodic macroblock pattern continuation and mismatch analysis
        t_pat, t_reps = cls.get_periodic_pattern(raw_a, from_head=False)
        h_pat, h_reps = cls.get_periodic_pattern(raw_b, from_head=True)

        if t_pat and h_pat:
            if t_pat == h_pat:
                score = 0.99
                explanations.append(f"High-confidence boundary match: Periodic macroblock pattern 0x{t_pat.hex().upper()} continuation ({t_reps}x in tail, {h_reps}x in head)")
            else:
                score = 0.02
                explanations.append(f"Incompatible periodic boundary pattern: Tail 0x{t_pat.hex().upper()} cannot continue into Head 0x{h_pat.hex().upper()}")
                return 0.02, explanations
        elif h_pat and h_reps >= 2 and not t_pat:
            score = 0.05
            explanations.append(f"Boundary mismatch: Fragment B begins in repeating macroblock pattern 0x{h_pat.hex().upper()} with no matching predecessor pattern")
            return 0.05, explanations
        elif t_pat and t_reps >= 2 and not h_pat:
            score = 0.05
            explanations.append(f"Boundary mismatch: Fragment A ends in repeating macroblock pattern 0x{t_pat.hex().upper()} with no matching successor pattern")
            return 0.05, explanations

        # 2. Check for split marker at boundary (tail_a ends with 0xFF)
        if raw_a[-1] == 0xFF:
            first_b = raw_b[0]
            if first_b == 0x00:
                score = max(score, 0.98)
                explanations.append("Perfect boundary match: Split byte stuffing (0xFF in A completed by 0x00 in B)")
            elif first_b in JPEG_MARKER_NAMES:
                marker_name = JPEG_MARKER_NAMES[first_b]
                score = max(score, 0.98)
                explanations.append(f"Perfect boundary match: Split JPEG marker 0xFF{first_b:02X} ({marker_name}) across fragment boundary")
            else:
                score = 0.02
                explanations.append(f"Boundary syntax error: Dangling 0xFF in A followed by invalid marker code 0x{first_b:02X} in B")
                return 0.02, explanations

        # 3. Check for split 2-byte marker prefix
        if len(raw_a) >= 2 and raw_a[-2] == 0xFF:
            marker_code = raw_a[-1]
            if marker_code in JPEG_MARKER_NAMES:
                score = max(score, 0.95)
                explanations.append(f"Marker header 0xFF{marker_code:02X} at boundary completed by length in B")

        # 4. In compressed entropy data, check whether seam creates illegal marker codes
        for i in range(len(seam_32) - 1):
            if seam_32[i] == 0xFF:
                next_byte = seam_32[i + 1]
                is_boundary_cross = (i < 16 and (i + 1) >= 16)
                if is_boundary_cross:
                    if next_byte not in (0x00, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD9, 0xDA):
                        score = min(score, 0.05)
                        explanations.append(f"Illegal marker cross sequence 0xFF{next_byte:02X} generated across seam")
                        return 0.05, explanations

        # 5. Compute seam entropy vs component entropy
        seam_entropy = JPEGAnalysisService.calculate_entropy(seam_32)
        if seam_entropy >= 7.0 and score < 0.80:
            score = max(score, 0.78)
            explanations.append(f"High-entropy continuity across boundary seam ({seam_entropy:.2f} bits/byte)")
        elif seam_entropy < 4.0 and score >= 0.70:
            explanations.append(f"Low-entropy boundary transition ({seam_entropy:.2f} bits/byte)")

        return round(min(score, 1.0), 3), explanations

    @classmethod
    def evaluate_parser_score(
        cls,
        raw_a: bytes,
        raw_b: bytes,
        feat_a: Dict[str, Any],
        feat_b: Dict[str, Any]
    ) -> Tuple[float, List[str]]:
        """
        Validate concatenation A + B using JPEG decoding / incremental parsing checks.
        """
        from app.services.jpeg_analysis_service import FastJPEGStreamParser
        explanations = []
        combined = raw_a + raw_b

        starts_soi_a = feat_a.get("starts_with_soi", False)
        starts_soi_b = feat_b.get("starts_with_soi", False)
        ends_eoi_a = feat_a.get("ends_with_eoi", False)
        ends_eoi_b = feat_b.get("ends_with_eoi", False)

        # Fatal transitions
        if starts_soi_b:
            explanations.append("Severe penalty: Target fragment B starts with SOI (FFD8); cannot be preceded by another fragment")
            return 0.001, explanations

        if ends_eoi_a:
            explanations.append("Severe penalty: Preceding fragment A ends with EOI (FFD9); cannot continue into another fragment")
            return 0.001, explanations

        # Full image trial: if A has SOI and B has EOI
        if starts_soi_a and ends_eoi_b:
            try:
                img = Image.open(io.BytesIO(combined))
                img.verify()
                explanations.append("Complete JPEG validation: Full image decompresses and verifies with decoder")
                return 1.0, explanations
            except Exception as e:
                # Missing intermediate fragments
                explanations.append(f"Full decode failed (intermediate fragments expected): {str(e)[:50]}")
                return 0.35, explanations

        # Incremental bitstream verification if A starts with SOI and contains SOS
        if starts_soi_a and feat_a.get("contains_sos"):
            try:
                dht = JPEGAnalysisService.extract_dht_tables(raw_a)
                if dht:
                    # Find SOS offset in raw_a
                    sos_idx = raw_a.find(b"\xFF\xDA")
                    if sos_idx != -1 and sos_idx + 4 < len(raw_a):
                        L = (raw_a[sos_idx + 2] << 8) | raw_a[sos_idx + 3]
                        start_offset = sos_idx + 2 + L
                        parser = FastJPEGStreamParser(dht)
                        mcu_a, res_a = parser.feed(raw_a, is_first=True, start_offset=start_offset)
                        mcu_b, res_b = parser.feed(raw_b, is_first=False)
                        if "AC_OVERFLOW" in res_b or "INVALID" in res_b:
                            explanations.append(f"Bitstream parsing failure at seam: {res_b}")
                            return 0.05, explanations
                        elif mcu_b >= mcu_a:
                            explanations.append(f"Bitstream verified: Parsed across seam without errors ({mcu_b} MCUs decoded)")
                            return 0.95, explanations
            except Exception as e:
                pass

        # Incremental marker verification for header combinations
        if starts_soi_a:
            try:
                markers = JPEGAnalysisService.scan_markers(combined)
                if len(markers) >= 2:
                    explanations.append(f"Parser successfully verified {len(markers)} markers in A+B prefix")
                    return 0.90, explanations
            except Exception as e:
                explanations.append(f"Marker parser error across prefix: {str(e)[:50]}")
                return 0.20, explanations

        # Entropy data stream check: scan for unescaped 0xFF
        has_invalid_scan_sequence = False
        i = 0
        n = len(combined)
        while i < n - 1:
            if combined[i] == 0xFF:
                nb = combined[i + 1]
                if nb not in (0x00, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xC4, 0xC0, 0xC2, 0xE0, 0xE1, 0xFE, 0xDD):
                    has_invalid_scan_sequence = True
                    break
            i += 1

        if has_invalid_scan_sequence:
            explanations.append("Parser detected invalid unescaped byte sequence in combined stream")
            return 0.15, explanations

        explanations.append("Syntactically consistent JPEG byte stream across candidate concatenation")
        return 0.85, explanations


    @classmethod
    def calculate_total_score(
        cls,
        from_frag: Dict[str, Any],
        to_frag: Dict[str, Any],
        raw_a: bytes,
        raw_b: bytes,
        weights: Optional[Dict[str, float]] = None
    ) -> Dict[str, Any]:
        """
        Combine all available evidence sources into a transparent, normalized total_score.
        """
        w = dict(cls.DEFAULT_WEIGHTS)
        if weights:
            w.update(weights)

        feat_a = from_frag.get("jpeg_features") or {}
        feat_b = to_frag.get("jpeg_features") or {}

        # 1. Physical Score
        phys_score, phys_exp = cls.evaluate_physical_score(from_frag, to_frag)

        # 2. Structural Score
        struct_score, struct_exps = cls.evaluate_structural_score(feat_a, feat_b)

        # 3. Boundary Score
        bound_score, bound_exps = cls.evaluate_boundary_score(raw_a, raw_b)

        # 4. Parser Score
        parser_score, parser_exps = cls.evaluate_parser_score(raw_a, raw_b, feat_a, feat_b)

        # 5. ML Score (Architecture ready, null for now)
        ml_score = None
        ml_exp = "ML adjacency model inference: unavailable (deferred to future phase)"

        # Calculate normalized weighted total
        weighted_sum = 0.0
        total_weight = 0.0

        # Structural
        weighted_sum += struct_score * w["structural"]
        total_weight += w["structural"]

        # Boundary
        weighted_sum += bound_score * w["boundary"]
        total_weight += w["boundary"]

        # Parser
        weighted_sum += parser_score * w["parser"]
        total_weight += w["parser"]

        # Physical (if available)
        if phys_score is not None:
            weighted_sum += phys_score * w["physical"]
            total_weight += w["physical"]

        # ML (if available)
        if ml_score is not None:
            weighted_sum += ml_score * w["ml"]
            total_weight += w["ml"]

        total_score = round(weighted_sum / total_weight, 4) if total_weight > 0 else 0.0

        all_explanations = []
        all_explanations.extend(struct_exps)
        all_explanations.extend(bound_exps)
        all_explanations.extend(parser_exps)
        if phys_exp:
            all_explanations.append(phys_exp)
        all_explanations.append(ml_exp)

        evidence = {
            "structural_score": struct_score,
            "boundary_score": bound_score,
            "parser_score": parser_score,
            "physical_score": phys_score,
            "ml_score": ml_score,
            "total_score": total_score,
            "active_weights": {k: v for k, v in w.items() if (k != "physical" or phys_score is not None) and (k != "ml" or ml_score is not None)},
            "explanations": all_explanations
        }

        return {
            "physical_score": phys_score,
            "structural_score": struct_score,
            "boundary_score": bound_score,
            "parser_score": parser_score,
            "ml_score": ml_score,
            "total_score": total_score,
            "evidence": evidence
        }
