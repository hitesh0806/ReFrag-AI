
import os, time

dir_path = r'test_dataset\mixed_dataset'
target_names = [f'fragment_{i:02d}' for i in range(1, 13)]
files = os.listdir(dir_path)
ordered_targets = []
for p in target_names:
    ordered_targets.append([f for f in files if f.startswith(p)][0])

full_data = b''.join(open(os.path.join(dir_path, f), 'rb').read() for f in ordered_targets)

data_01 = open(os.path.join(dir_path, 'fragment_01_42a0f2.bin'), 'rb').read()
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

def test_stream(data, start_offset=623):
    scan = []
    idx = start_offset
    while idx < len(data):
        if data[idx] == 0xff:
            if idx + 1 < len(data):
                if data[idx+1] == 0x00:
                    scan.append(0xff)
                    idx += 2
                    continue
                elif 0xd0 <= data[idx+1] <= 0xd7:
                    idx += 2
                    continue
                elif data[idx+1] == 0xd9:
                    break
                else:
                    idx += 1
                    continue
            else:
                break
        else:
            scan.append(data[idx])
            idx += 1
            
    bit_pos = 0
    total_bits = len(scan) * 8
    def read_bit():
        nonlocal bit_pos
        if bit_pos >= total_bits: return None
        b = (scan[bit_pos >> 3] >> (7 - (bit_pos & 7))) & 1
        bit_pos += 1
        return b
    def read_sym(trie):
        node = trie
        while 'sym' not in node:
            b = read_bit()
            if b is None or b not in node: return None
            node = node[b]
        return node['sym']
    def read_bits(n):
        nonlocal bit_pos
        if bit_pos + n > total_bits: return None
        val = 0
        for _ in range(n): val = (val << 1) | read_bit()
        return val

    blocks = [(0, 0, 1, 0)]*4 + [(0, 1, 1, 1), (0, 1, 1, 1)]
    mcu = 0
    while bit_pos < total_bits - 16:
        for dc_tc, dc_tid, ac_tc, ac_tid in blocks:
            dc_sym = read_sym(dht_tables[(dc_tc, dc_tid)])
            if dc_sym is None: return mcu, 'INVALID_DC_HUFFMAN'
            if dc_sym > 0:
                if read_bits(dc_sym) is None: return mcu, 'TRUNCATED_BITS'
            k = 1
            while k < 64:
                ac_sym = read_sym(dht_tables[(ac_tc, ac_tid)])
                if ac_sym is None: return mcu, 'INVALID_AC_HUFFMAN'
                if ac_sym == 0x00: break
                k += (ac_sym >> 4)
                if k >= 64: return mcu, 'AC_OVERFLOW'
                s = ac_sym & 0x0f
                if s > 0:
                    if read_bits(s) is None: return mcu, 'TRUNCATED_BITS'
                k += 1
        mcu += 1
    return mcu, 'COMPLETE'

t0 = time.time()
mcu, res = test_stream(full_data)
t1 = time.time()
print(f'Execution time: {(t1-t0)*1000:.2f}ms, MCUs: {mcu}, res: {res}')
