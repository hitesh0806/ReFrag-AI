import os
import sys
import glob

sys.path.insert(0, 'backend')
from app.services.jpeg_analysis_service import JPEGAnalysisService, FastJPEGStreamParser
from app.services.scoring_service import ScoringService
from app.services.validation_service import ValidationService

dir_path = r'test_dataset\mixed_dataset'
files = sorted(os.listdir(dir_path))
all_frags = {f: open(os.path.join(dir_path, f), 'rb').read() for f in files}

# Build fragment objects
fragments = []
for idx, f in enumerate(files):
    feats = JPEGAnalysisService.extract_features(all_frags[f])
    fragments.append({
        'id': f,
        'source_filename': f,
        'raw_content': all_frags[f],
        'features': feats['features'],
        'classification': feats['classification'],
        'entropy': feats['entropy'],
        'starts_with_soi': feats['features']['starts_with_soi'],
        'ends_with_eoi': feats['features']['ends_with_eoi'],
        'sof_info': feats.get('sof_info'),
    })

frag_map = {f['id']: f for f in fragments}

# 1. Identify start, end, and interior
start_nodes = [f for f in fragments if f['starts_with_soi']]
end_nodes = [f for f in fragments if f['ends_with_eoi']]
interior_nodes = [f for f in fragments if not f['starts_with_soi'] and not f['ends_with_eoi']]

print(f"Start nodes ({len(start_nodes)}): {[f['id'] for f in start_nodes]}")
print(f"End nodes ({len(end_nodes)}): {[f['id'] for f in end_nodes]}")
print(f"Interior nodes ({len(interior_nodes)}): {[f['id'] for f in interior_nodes]}")

# 2. Find high-confidence boundary contigs
# For pairs (A, B) where boundary score >= 0.85
best_next = {}
best_prev = {}

for fA in fragments:
    # A cannot end with EOI to have a next
    if fA['ends_with_eoi']: continue
    for fB in fragments:
        if fA['id'] == fB['id']: continue
        # B cannot start with SOI
        if fB['starts_with_soi']: continue
        
        # calculate seam score
        sc, exps = ScoringService.evaluate_boundary_score(fA['raw_content'], fB['raw_content'])
        if sc >= 0.85:
            # Check if this is the best for fA
            if fA['id'] not in best_next or sc > best_next[fA['id']][1]:
                best_next[fA['id']] = (fB['id'], sc)

# Mutual / confident merges
contig_next = {}
contig_prev = {}
for aid, (bid, sc) in best_next.items():
    # Only merge if bid doesn't have a better prev
    contig_next[aid] = bid
    contig_prev[bid] = aid

# Build contigs (chains of fragments)
visited_in_contig = set()
contigs = [] # list of lists of fragment_ids

for f in fragments:
    fid = f['id']
    if fid in visited_in_contig: continue
    if fid in contig_prev: continue # start from head of contig
    
    # Trace chain
    chain = [fid]
    curr = fid
    while curr in contig_next:
        nxt = contig_next[curr]
        if nxt in chain: break # prevent cycles
        chain.append(nxt)
        curr = nxt
        
    for x in chain:
        visited_in_contig.add(x)
    contigs.append(chain)

print(f"\nFormed {len(contigs)} contigs:")
for c in contigs:
    print(f"  Contig ({len(c)} frags): {c}")

# 3. For each candidate start fragment, explore candidate paths to EOI
candidate_chains = []

for s_frag in start_nodes:
    start_fid = s_frag['id']
    sof_info = s_frag['features'].get('sof_info') or JPEGAnalysisService.extract_sof_info(s_frag['raw_content'])
    expected_mcus = sof_info.get('expected_mcus', 0) if sof_info else 0
    dht_tables = JPEGAnalysisService.extract_dht_tables(s_frag['raw_content'])
    
    print(f"\n--- Exploring paths from {start_fid} (expected MCUs: {expected_mcus}) ---")
    
    # Contigs available (excluding other start nodes)
    avail_contigs = []
    start_contig = None
    for c in contigs:
        if c[0] == start_fid:
            start_contig = c
        elif any(frag_map[x]['starts_with_soi'] for x in c):
            # Contains another SOI, cannot use
            continue
        else:
            avail_contigs.append(c)
            
    if not start_contig:
        start_contig = [start_fid]
        
    print(f"Start contig: {start_contig}, available other contigs: {len(avail_contigs)}")
    
    # Beam search across contigs
    # State: (chain_of_fragments, parser, mcu_count, score)
    parser = FastJPEGStreamParser(dht_tables) if dht_tables else None
    start_data = b''.join(frag_map[x]['raw_content'] for x in start_contig)
    
    sos_idx = start_data.find(b"\xFF\xDA")
    start_offset = 0
    if sos_idx != -1 and sos_idx + 4 < len(start_data):
        sos_len = (start_data[sos_idx + 2] << 8) | start_data[sos_idx + 3]
        start_offset = sos_idx + 2 + sos_len
        
    init_mcu = 0
    init_res = "OK"
    if parser:
        init_mcu, init_res = parser.feed(start_data, is_first=True, start_offset=start_offset)
        
    # If start contig already ends with EOI
    if frag_map[start_contig[-1]]['ends_with_eoi']:
        candidate_chains.append(start_contig)
        print(f"  Start contig completes itself: {start_contig}")
        continue
        
    # Search permutations of remaining contigs
    beam = [(start_contig, parser.snapshot() if parser else None, init_mcu, 1.0)]
    
    step = 0
    while beam and step < len(avail_contigs) + 2:
        new_beam = []
        for curr_chain, snap, curr_mcus, curr_sc in beam:
            last_fid = curr_chain[-1]
            if frag_map[last_fid]['ends_with_eoi']:
                # Reached end
                continue
                
            curr_used = set(curr_chain)
            
            # Next contig candidates
            for next_c in avail_contigs:
                if any(x in curr_used for x in next_c): continue
                
                # Test appending next_c
                c_data = b''.join(frag_map[x]['raw_content'] for x in next_c)
                is_terminal = frag_map[next_c[-1]]['ends_with_eoi']
                
                if parser and snap:
                    parser.restore(snap)
                    mcu, res = parser.feed(c_data, is_first=False)
                    if "OVERFLOW" in res or "INVALID" in res:
                        continue
                    if is_terminal and expected_mcus > 0 and mcu < expected_mcus:
                        continue
                        
                    new_snap = parser.snapshot()
                    delta_mcu = mcu - curr_mcus
                    score = curr_sc + (1000.0 if (is_terminal and mcu >= expected_mcus) else (delta_mcu + 10.0))
                    new_beam.append((curr_chain + next_c, new_snap, mcu, score))
                else:
                    # Baseline concatenation
                    new_beam.append((curr_chain + next_c, None, 0, curr_sc + 1.0))
                    
        if not new_beam:
            break
            
        new_beam.sort(key=lambda x: x[3], reverse=True)
        beam = new_beam[:20]
        
        # Check if top candidate reached terminal with full MCUs
        for p, s, m, sc in beam:
            if frag_map[p[-1]]['ends_with_eoi']:
                if expected_mcus == 0 or m >= expected_mcus:
                    candidate_chains.append(p)
                    print(f"  FOUND COMPLETE PATH: {len(p)} frags, {m} MCUs")
                    break
        if candidate_chains and candidate_chains[-1][0] == start_fid:
            break
        step += 1

print("\n=== ALL RECONSTRUCTION CANDIDATES FOUND ===")
for i, c in enumerate(candidate_chains):
    raw_b = b''.join(frag_map[x]['raw_content'] for x in c)
    status, score, val_res = ValidationService.validate_jpeg(raw_b)
    print(f"Candidate {i+1}: {len(c)} fragments, {len(raw_b)} bytes, status={status}, score={score:.2f}")
    print(f"  Order: {c}")
