import os
import time

dir_path = r'test_dataset\mixed_dataset'
files = sorted(os.listdir(dir_path))
all_frags = {f: open(os.path.join(dir_path, f), 'rb').read() for f in files}

# Extract DHT tables from fragment_01
data_01 = all_frags['fragment_01_42a0f2.bin']
dht_tables = {}
i = 0
while i < len(data_01) - 1:
    if data_01[i] == 0xff and data_01[i+1] == 0xc4:
        L = (data_01[i+2]<<8) | data_01[i+3]
        payload = data_01[i+4:i+2+L]
        t_class = payload[0] >> 4
        t_id = payload[0] & 0x0f
        counts = list(payload[1:17])
        symbols = list(payload[17:])
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
    else:
        i += 1

def unescape_scan(data, start_offset=0):
    scan = bytearray()
    idx = start_offset
    n = len(data)
    while idx < n:
        b = data[idx]
        if b == 0xff:
            if idx + 1 < n:
                nb = data[idx+1]
                if nb == 0x00:
                    scan.append(0xff)
                    idx += 2
                    continue
                elif 0xd0 <= nb <= 0xd7:
                    idx += 2
                    continue
                elif nb == 0xd9:
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

class JPEGStreamParser:
    def __init__(self, dht):
        self.dht = dht
        self.blocks_in_mcu = [(0, 0, 1, 0)]*4 + [(0, 1, 1, 1), (0, 1, 1, 1)]
        self.reset()
        
    def reset(self):
        self.scan = bytearray()
        self.bit_pos = 0
        self.mcu = 0
        self.block_idx = 0
        self.k = 0
        self.node = None
        self.awaiting_bits = 0
        self.state = 'DC_SYM'

    def snapshot(self):
        return (len(self.scan), self.bit_pos, self.mcu, self.block_idx, self.k, self.node, self.awaiting_bits, self.state)

    def restore(self, snap):
        saved_len, self.bit_pos, self.mcu, self.block_idx, self.k, self.node, self.awaiting_bits, self.state = snap
        del self.scan[saved_len:]
        
    def feed(self, new_bytes, is_first=False, start_offset=0):
        if is_first:
            self.reset()
            self.scan = unescape_scan(new_bytes, start_offset)
        else:
            self.scan.extend(unescape_scan(new_bytes, 0))
            
        total_bits = len(self.scan) * 8
        blocks = self.blocks_in_mcu
        
        while self.bit_pos < total_bits:
            dc_tc, dc_tid, ac_tc, ac_tid = blocks[self.block_idx]
            
            if self.state == 'DC_SYM':
                if self.node is None:
                    self.node = self.dht[(dc_tc, dc_tid)]
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
                    self.node = self.dht[(ac_tc, ac_tid)]
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
                        s = ac_sym & 0x0f
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

if __name__ == '__main__':
    start_fid = 'fragment_01_42a0f2.bin'
    parser = JPEGStreamParser(dht_tables)
    parser.feed(all_frags[start_fid], is_first=True, start_offset=623)

    soi_files = {f for f, d in all_frags.items() if d[:2] == b'\xff\xd8'}
    eoi_files = {f for f, d in all_frags.items() if d[-2:] == b'\xff\xd9'}

    path = [start_fid]
    expected_mcus = 3525

    t0 = time.time()
    while len(path) < 20:
        curr = path[-1]
        if curr in eoi_files and parser.mcu >= expected_mcus:
            break
            
        snap = parser.snapshot()
        curr_mcu = parser.mcu
        
        candidates = []
        for cand in files:
            if cand in path: continue
            if cand in soi_files: continue
            
            # Test candidate
            mcus, res = parser.feed(all_frags[cand], is_first=False)
            is_eoi = cand in eoi_files
            
            # If it's an EOI fragment, it should ONLY be accepted if it completes the target MCUs!
            if is_eoi:
                if mcus >= expected_mcus:
                    candidates.append((cand, mcus - curr_mcu, mcus, 1000.0, res))
                else:
                    candidates.append((cand, mcus - curr_mcu, mcus, -1000.0, res))
            else:
                if res == 'NEED_BITS' and mcus >= curr_mcu:
                    delta_mcu = mcus - curr_mcu
                    score = delta_mcu + 10.0
                    candidates.append((cand, delta_mcu, mcus, score, res))
                else:
                    candidates.append((cand, mcus - curr_mcu, mcus, -500.0, res))
                    
            parser.restore(snap)
            
        candidates.sort(key=lambda x: x[3], reverse=True)
        if not candidates:
            break
        best = candidates[0]
        print(f"Step {len(path)} -> picked {best[0]} (score={best[3]}, d_mcu={best[1]}, tot_mcu={best[2]}, res={best[4]})")
        path.append(best[0])
        parser.feed(all_frags[best[0]], is_first=False)
        if best[0] in eoi_files and parser.mcu >= expected_mcus:
            print("Target complete!")
            break

    t1 = time.time()
    print(f"\nExecution time: {(t1-t0)*1000:.2f}ms")
    print(f"Final Path ({len(path)} fragments):")
    for i, f in enumerate(path):
        print(f"  {i+1}: {f}")

    full_bytes = b''.join(all_frags[f] for f in path)
    import hashlib
    print(f"Reconstructed size: {len(full_bytes)}")
    print(f"Reconstructed SHA256: {hashlib.sha256(full_bytes).hexdigest()}")

