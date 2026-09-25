import os
import sys
import io
import hashlib
from PIL import Image

sys.path.insert(0, 'backend')
from app.services.jpeg_analysis_service import JPEGAnalysisService, FastJPEGStreamParser
from app.services.scoring_service import ScoringService

dir_path = r'test_dataset\mixed_dataset'
all_frags = {f: open(os.path.join(dir_path, f), 'rb').read() for f in sorted(os.listdir(dir_path))}

def get_periodic_head_pattern(data, min_reps=2):
    head = data[:32]
    for plen in (8, 4, 3, 2):
        pat = head[:plen]
        reps = 0
        idx = 0
        while idx + plen <= len(head) and head[idx:idx+plen] == pat:
            reps += 1
            idx += plen
        if reps >= min_reps:
            return pat, reps
    return None, 0

def get_periodic_tail_pattern(data, min_reps=2):
    tail = data[-32:]
    for plen in (8, 4, 3, 2):
        pat = tail[-plen:]
        reps = 0
        idx = len(tail)
        while idx >= plen and tail[idx-plen:idx] == pat:
            reps += 1
            idx -= plen
        if reps >= min_reps:
            return pat, reps
    return None, 0

start_nodes = [f for f, d in all_frags.items() if d[:2] == b'\xFF\xD8']
end_nodes = [f for f, d in all_frags.items() if d[-2:] == b'\xFF\xD9']

print('Start nodes:', start_nodes)
print('End nodes:', end_nodes)

def reconstruct_target():
    all_chains = []
    
    for s_frag in start_nodes:
        d_start = all_frags[s_frag]
        sof = JPEGAnalysisService.extract_sof_info(d_start)
        if not sof: continue
        exp_mcus = sof['expected_mcus']
        dht = JPEGAnalysisService.extract_dht_tables(d_start)
        if not dht: continue
        
        sos_idx = d_start.find(b'\xFF\xDA')
        sos_len = (d_start[sos_idx + 2] << 8) | d_start[sos_idx + 3]
        start_offset = sos_idx + 2 + sos_len
        
        parser = FastJPEGStreamParser(dht)
        mcu0, res0 = parser.feed(d_start, is_first=True, start_offset=start_offset)
        snap0 = parser.snapshot()
        
        def dfs(path, snap, cur_mcu):
            curr = path[-1]
            if curr in end_nodes:
                if cur_mcu >= exp_mcus:
                    raw_b = b''.join(all_frags[x] for x in path)
                    try:
                        img = Image.open(io.BytesIO(raw_b))
                        img.verify()
                        img2 = Image.open(io.BytesIO(raw_b))
                        img2.load()
                        all_chains.append({
                            'start': s_frag,
                            'path': list(path),
                            'length': len(path),
                            'size': len(raw_b),
                            'mcus': cur_mcu,
                            'exp_mcus': exp_mcus,
                            'img_size': img2.size,
                            'bytes': raw_b
                        })
                    except Exception:
                        pass
                return
                
            used = set(path)
            t_pat, t_reps = get_periodic_tail_pattern(all_frags[curr])
            
            for cand in all_frags:
                if cand in used: continue
                if cand in start_nodes: continue
                
                is_end = cand in end_nodes
                
                h_pat, h_reps = get_periodic_head_pattern(all_frags[cand])
                if h_pat and h_pat != t_pat: continue
                if t_pat and h_pat != t_pat: continue
                
                parser.restore(snap)
                mcus, res = parser.feed(all_frags[cand], is_first=False)
                if 'OVERFLOW' in res or 'INVALID' in res:
                    continue
                    
                if is_end and mcus < exp_mcus:
                    continue
                    
                new_snap = parser.snapshot()
                path.append(cand)
                dfs(path, new_snap, mcus)
                path.pop()
                
        dfs([s_frag], snap0, mcu0)
        
    return all_chains

chains = reconstruct_target()
print('Total coherent reconstruction chains found:', len(chains))
for i, c in enumerate(chains):
    sha = hashlib.sha256(c['bytes']).hexdigest()
    st = c['start']
    l = c['length']
    sz = c['size']
    mc = c['mcus']
    emc = c['exp_mcus']
    ims = c['img_size']
    p = c['path']
    print(f'Chain {i+1}: Start={st}, Frags={l}, Size={sz} B, MCUs={mc}/{emc}, Img={ims}, SHA={sha}')
    print(f'  Path: {p}')
