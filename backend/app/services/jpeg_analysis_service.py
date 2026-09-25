import math
from typing import List, Dict, Any, Optional, Tuple

JPEG_MARKER_NAMES: Dict[int, str] = {
    0xD8: "SOI",
    0xD9: "EOI",
    0xDA: "SOS",
    0xDB: "DQT",
    0xC4: "DHT",
    0xDD: "DRI",
    0xFE: "COM",
    0xC0: "SOF0",
    0xC1: "SOF1",
    0xC2: "SOF2",
    0xC3: "SOF3",
    0xC5: "SOF5",
    0xC6: "SOF6",
    0xC7: "SOF7",
    0xC9: "SOF9",
    0xCA: "SOF10",
    0xCB: "SOF11",
    0xCD: "SOF13",
    0xCE: "SOF14",
    0xCF: "SOF15",
    0xE0: "APP0",
    0xE1: "APP1",
    0xE2: "APP2",
    0xE3: "APP3",
    0xE4: "APP4",
    0xE5: "APP5",
    0xE6: "APP6",
    0xE7: "APP7",
    0xE8: "APP8",
    0xE9: "APP9",
    0xEA: "APP10",
    0xEB: "APP11",
    0xEC: "APP12",
    0xED: "APP13",
    0xEE: "APP14",
    0xEF: "APP15",
    0xD0: "RST0",
    0xD1: "RST1",
    0xD2: "RST2",
    0xD3: "RST3",
    0xD4: "RST4",
    0xD5: "RST5",
    0xD6: "RST6",
    0xD7: "RST7",
}

class JPEGAnalysisService:
    """
    Forensic JPEG Fragment Analyzer.
    Inspects raw fragment bytes, scans for markers, computes Shannon entropy,
    and extracts forensic structural characteristics.
    """

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """
        Compute Shannon entropy of the byte sequence in bits per byte (0.0 to 8.0).
        """
        if not data:
            return 0.0

        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1

        total = len(data)
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)

        return round(entropy, 4)

    @classmethod
    def scan_markers(cls, data: bytes) -> List[Dict[str, Any]]:
        """
        Scan byte stream for valid JPEG markers, distinguishing between true markers
        and byte stuffing (0xFF00) inside entropy-coded scan data.
        """
        markers = []
        i = 0
        n = len(data)

        while i < n - 1:
            if data[i] == 0xFF:
                # Skip consecutive 0xFF padding
                j = i + 1
                while j < n and data[j] == 0xFF:
                    j += 1

                if j < n:
                    marker_byte = data[j]
                    # 0x00 is byte stuffing in entropy data, not a marker
                    if marker_byte == 0x00:
                        i = j + 1
                        continue

                    name = JPEG_MARKER_NAMES.get(marker_byte, f"UNKNOWN_FF{marker_byte:02X}")
                    markers.append({
                        "offset": i,
                        "marker_hex": f"FF{marker_byte:02X}",
                        "name": name,
                    })

                    # If marker has length (non-standalone markers), read payload length
                    # Standalone markers: SOI (D8), EOI (D9), RST0-RST7 (D0-D7)
                    is_standalone = marker_byte in (0xD8, 0xD9) or (0xD0 <= marker_byte <= 0xD7)
                    if not is_standalone and j + 2 < n:
                        length = (data[j + 1] << 8) | data[j + 2]
                        markers[-1]["declared_length"] = length

                    i = j + 1
                else:
                    break
            else:
                i += 1

        return markers

    @classmethod
    def classify_fragment(
        cls,
        data: bytes,
        markers: List[Dict[str, Any]],
        entropy: float
    ) -> Tuple[str, float]:
        """
        Classify fragment into structural category and return confidence.
        Categories:
        - HEADER_FRAGMENT: starts with SOI (FF D8)
        - ENDING_FRAGMENT: ends with EOI (FF D9)
        - STRUCTURAL_FRAGMENT: contains structural tables (DQT, DHT, SOF, SOS) without SOI/EOI
        - METADATA_FRAGMENT: contains APPx/COM without SOI
        - ENTROPY_DATA_FRAGMENT: high entropy scan data
        - UNKNOWN_JPEG_FRAGMENT: unclassified
        """
        starts_with_soi = len(data) >= 2 and data[0] == 0xFF and data[1] == 0xD8
        ends_with_eoi = len(data) >= 2 and data[-2] == 0xFF and data[-1] == 0xD9

        marker_names = [m["name"] for m in markers]

        if starts_with_soi:
            return "HEADER_FRAGMENT", 0.98

        if ends_with_eoi:
            return "ENDING_FRAGMENT", 0.98

        structural_markers = {"DQT", "DHT", "SOF0", "SOF1", "SOF2", "SOS", "DRI"}
        has_structural = any(name in structural_markers for name in marker_names)
        has_metadata = any(name.startswith("APP") or name == "COM" for name in marker_names)

        if has_structural:
            return "STRUCTURAL_FRAGMENT", 0.92

        if has_metadata:
            return "METADATA_FRAGMENT", 0.88

        # In entropy-coded scan data, Shannon entropy is typically >= 7.0
        # Check for presence of byte-stuffing \xFF\x00
        has_stuffing = b"\xFF\x00" in data
        if entropy >= 7.0 or has_stuffing:
            return "ENTROPY_DATA_FRAGMENT", 0.85

        if entropy >= 6.0:
            return "UNKNOWN_JPEG_FRAGMENT", 0.60

        return "UNKNOWN_JPEG_FRAGMENT", 0.40

    @classmethod
    def extract_sof_info(cls, data: bytes) -> Optional[Dict[str, Any]]:
        """
        Extract SOF (Start of Frame) dimension and sampling metadata to compute expected MCUs.
        """
        i = 0
        n = len(data)
        while i < n - 1:
            if data[i] == 0xFF:
                m = data[i + 1]
                if m in (0xC0, 0xC1, 0xC2):
                    if i + 9 < n:
                        h = (data[i + 5] << 8) | data[i + 6]
                        w = (data[i + 7] << 8) | data[i + 8]
                        components = data[i + 9]
                        
                        # Inspect sampling factors for component 1 (Luminance Y)
                        # Offset i + 10 is comp ID, i + 11 is sampling factor
                        h_samp = 2
                        v_samp = 2
                        if i + 11 < n:
                            samp = data[i + 11]
                            h_samp = samp >> 4
                            v_samp = samp & 0x0F
                            if h_samp == 0: h_samp = 1
                            if v_samp == 0: v_samp = 1

                        mcu_w_pixels = h_samp * 8
                        mcu_h_pixels = v_samp * 8
                        mcu_cols = (w + mcu_w_pixels - 1) // mcu_w_pixels
                        mcu_rows = (h + mcu_h_pixels - 1) // mcu_h_pixels
                        expected_mcus = mcu_cols * mcu_rows

                        return {
                            "width": w,
                            "height": h,
                            "components": components,
                            "h_samp": h_samp,
                            "v_samp": v_samp,
                            "mcu_cols": mcu_cols,
                            "mcu_rows": mcu_rows,
                            "expected_mcus": expected_mcus,
                            "sof_marker": f"FF{m:02X}"
                        }
                elif m not in (0xD8, 0xD9) and (m < 0xD0 or m > 0xD7) and i + 3 < n:
                    L = (data[i + 2] << 8) | data[i + 3]
                    i += 2 + L
                    continue
                i += 2
            else:
                i += 1
        return None

    @classmethod
    def extract_dht_tables(cls, data: bytes) -> Dict[Tuple[int, int], Any]:
        """
        Extract Huffman tables (DHT) and build canonical bit-tries for bitstream parsing.
        Key: (class, table_id) where class 0=DC, 1=AC
        """
        dht_tables = {}
        i = 0
        n = len(data)
        while i < n - 1:
            if data[i] == 0xFF and data[i + 1] == 0xC4:
                if i + 3 < n:
                    L = (data[i + 2] << 8) | data[i + 3]
                    payload = data[i + 4:i + 2 + L]
                    pidx = 0
                    while pidx < len(payload):
                        header = payload[pidx]
                        t_class = header >> 4
                        t_id = header & 0x0F
                        counts = list(payload[pidx + 1:pidx + 17])
                        num_syms = sum(counts)
                        symbols = list(payload[pidx + 17:pidx + 17 + num_syms])
                        pidx += 17 + num_syms

                        # Build canonical prefix trie
                        trie = {}
                        code = 0
                        sym_idx = 0
                        for bits in range(1, 17):
                            cnt = counts[bits - 1]
                            for _ in range(cnt):
                                sym = symbols[sym_idx]
                                sym_idx += 1
                                node = trie
                                for b in range(bits - 1, -1, -1):
                                    bit = (code >> b) & 1
                                    if bit not in node:
                                        node[bit] = {}
                                    node = node[bit]
                                node['sym'] = sym
                                code += 1
                            code <<= 1
                        dht_tables[(t_class, t_id)] = trie
                    i += 2 + L
                    continue
            i += 1
        return dht_tables

    @classmethod
    def extract_features(cls, data: bytes) -> Dict[str, Any]:
        """
        Comprehensive forensic feature extraction for a single fragment.
        """
        byte_len = len(data)
        entropy = cls.calculate_entropy(data)
        markers = cls.scan_markers(data)

        starts_with_soi = byte_len >= 2 and data[0] == 0xFF and data[1] == 0xD8
        ends_with_eoi = byte_len >= 2 and data[-2] == 0xFF and data[-1] == 0xD9

        marker_names = [m["name"] for m in markers]
        first_marker = marker_names[0] if marker_names else None
        last_marker = marker_names[-1] if marker_names else None

        classification, format_conf = cls.classify_fragment(data, markers, entropy)
        sof_info = cls.extract_sof_info(data) if starts_with_soi else None

        # Boundary inspection (first 16 and last 16 bytes)
        head_bytes = data[:16]
        tail_bytes = data[-16:]

        ends_with_partial_marker = byte_len > 0 and data[-1] == 0xFF
        starts_with_marker_continuation = byte_len > 0 and data[0] in JPEG_MARKER_NAMES

        has_byte_stuffing = b"\xFF\x00" in data
        contains_sos = "SOS" in marker_names

        features = {
            "starts_with_soi": starts_with_soi,
            "ends_with_eoi": ends_with_eoi,
            "first_marker": first_marker,
            "last_marker": last_marker,
            "marker_sequence": marker_names,
            "marker_count": len(markers),
            "contains_sos": contains_sos,
            "has_byte_stuffing": has_byte_stuffing,
            "entropy": entropy,
            "byte_length": byte_len,
            "ends_with_partial_marker": ends_with_partial_marker,
            "starts_with_marker_continuation": starts_with_marker_continuation,
            "head_hex": head_bytes.hex().upper(),
            "tail_hex": tail_bytes.hex().upper(),
            "classification": classification,
            "detected_format_confidence": format_conf,
            "sof_info": sof_info,
        }

        return {
            "features": features,
            "markers": markers,
            "classification": classification,
            "entropy": entropy,
            "format_confidence": format_conf,
            "sof_info": sof_info,
        }

class FastJPEGStreamParser:
    """
    High-speed stateful JPEG Huffman entropy bitstream validator.
    Inspects variable-length bit sequences across fragment boundaries,
    validating MCU progression and rejecting bitstream desynchronization.
    """
    def __init__(self, dht_tables: Dict[Tuple[int, int], Any]):
        self.dht = dht_tables
        self.blocks_in_mcu = [(0, 0, 1, 0)]*4 + [(0, 1, 1, 1), (0, 1, 1, 1)]
        self.reset()

    def reset(self):
        self.scan = bytearray()
        self.last_raw_byte = None
        self.bit_pos = 0
        self.mcu = 0
        self.block_idx = 0
        self.k = 0
        self.node = None
        self.awaiting_bits = 0
        self.state = 'DC_SYM'

    def snapshot(self):
        return (bytes(self.scan), self.last_raw_byte, self.bit_pos, self.mcu, self.block_idx, self.k, self.node, self.awaiting_bits, self.state)

    def restore(self, snap):
        saved_scan, self.last_raw_byte, self.bit_pos, self.mcu, self.block_idx, self.k, self.node, self.awaiting_bits, self.state = snap
        self.scan = bytearray(saved_scan)

    @staticmethod
    def unescape_bytes(data: bytes, start_offset: int = 0) -> bytearray:
        scan = bytearray()
        idx = start_offset
        n = len(data)
        while idx < n:
            b = data[idx]
            if b == 0xFF:
                if idx + 1 < n:
                    nb = data[idx + 1]
                    if nb == 0x00:
                        scan.append(0xFF)
                        idx += 2
                        continue
                    elif 0xD0 <= nb <= 0xD7:
                        idx += 2
                        continue
                    elif nb == 0xD9:
                        break
                    else:
                        idx += 1
                        continue
                else:
                    break
            else:
                scan.append(b)
                idx += 1
        return scan

    def feed(self, new_bytes: bytes, is_first: bool = False, start_offset: int = 0) -> Tuple[int, str]:
        if is_first:
            self.reset()
            chunk = new_bytes[start_offset:]
        else:
            chunk = new_bytes

        if not chunk:
            return self.mcu, 'NEED_BITS'

        idx = 0
        n = len(chunk)
        if not is_first and self.last_raw_byte == 0xFF:
            if chunk[0] == 0x00:
                self.scan.append(0xFF)
                idx = 1
            elif 0xD0 <= chunk[0] <= 0xD7:
                idx = 1
            elif chunk[0] == 0xD9:
                return self.mcu, 'NEED_BITS'

        while idx < n:
            b = chunk[idx]
            if b == 0xFF:
                if idx + 1 < n:
                    nb = chunk[idx + 1]
                    if nb == 0x00:
                        self.scan.append(0xFF)
                        idx += 2
                        continue
                    elif 0xD0 <= nb <= 0xD7:
                        idx += 2
                        continue
                    elif nb == 0xD9:
                        break
                    else:
                        idx += 1
                        continue
                else:
                    idx += 1
                    break
            else:
                self.scan.append(b)
                idx += 1

        self.last_raw_byte = chunk[-1] if chunk else None

        total_bits = len(self.scan) * 8
        blocks = self.blocks_in_mcu

        while self.bit_pos < total_bits:
            dc_tc, dc_tid, ac_tc, ac_tid = blocks[self.block_idx]

            if self.state == 'DC_SYM':
                if self.node is None:
                    self.node = self.dht.get((dc_tc, dc_tid))
                    if not self.node:
                        return self.mcu, 'MISSING_DHT'
                b = (self.scan[self.bit_pos >> 3] >> (7 - (self.bit_pos & 7))) & 1
                self.bit_pos += 1
                if b not in self.node:
                    return self.mcu, 'INVALID_DC'
                self.node = self.node[b]
                if 'sym' in self.node:
                    dc_sym = self.node['sym']
                    self.node = None
                    if dc_sym == 0:
                        self.state = 'AC_SYM'
                        self.k = 1
                    else:
                        self.state = 'DC_VAL'
                        self.awaiting_bits = dc_sym
                continue

            if self.state == 'DC_VAL':
                rem = total_bits - self.bit_pos
                if rem < self.awaiting_bits:
                    return self.mcu, 'NEED_BITS'
                self.bit_pos += self.awaiting_bits
                self.state = 'AC_SYM'
                self.k = 1
                continue

            if self.state == 'AC_SYM':
                if self.node is None:
                    self.node = self.dht.get((ac_tc, ac_tid))
                    if not self.node:
                        return self.mcu, 'MISSING_DHT'
                b = (self.scan[self.bit_pos >> 3] >> (7 - (self.bit_pos & 7))) & 1
                self.bit_pos += 1
                if b not in self.node:
                    return self.mcu, 'INVALID_AC'
                self.node = self.node[b]
                if 'sym' in self.node:
                    ac_sym = self.node['sym']
                    self.node = None
                    if ac_sym == 0x00:
                        self.block_idx += 1
                        if self.block_idx == 6:
                            self.block_idx = 0
                            self.mcu += 1
                        self.state = 'DC_SYM'
                    else:
                        r = ac_sym >> 4
                        s = ac_sym & 0x0F
                        self.k += r
                        if self.k >= 64:
                            return self.mcu, 'AC_OVERFLOW'
                        if s == 0:
                            self.k += 1
                            if self.k >= 64:
                                self.block_idx += 1
                                if self.block_idx == 6:
                                    self.block_idx = 0
                                    self.mcu += 1
                                self.state = 'DC_SYM'
                        else:
                            self.state = 'AC_VAL'
                            self.awaiting_bits = s
                continue

            if self.state == 'AC_VAL':
                rem = total_bits - self.bit_pos
                if rem < self.awaiting_bits:
                    return self.mcu, 'NEED_BITS'
                self.bit_pos += self.awaiting_bits
                self.k += 1
                if self.k >= 64:
                    self.block_idx += 1
                    if self.block_idx == 6:
                        self.block_idx = 0
                        self.mcu += 1
                    self.state = 'DC_SYM'
                else:
                    self.state = 'AC_SYM'
                continue

        return self.mcu, 'NEED_BITS'

