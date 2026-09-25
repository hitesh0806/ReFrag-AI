import io
import logging
from typing import List, Dict, Any, Optional, Tuple, Set
from sqlalchemy.orm import Session
from PIL import Image

from app.models.forensic import ForensicCase, ForensicArtifact, ForensicFragment, FragmentRelationship, ReconstructionCandidate
from app.services.jpeg_analysis_service import JPEGAnalysisService, FastJPEGStreamParser
from app.services.scoring_service import ScoringService
from app.services.validation_service import ValidationService

logger = logging.getLogger("refrag_ai.reconstruction")

class ReconstructionService:
    """
    Forensic JPEG Reconstruction Engine.
    Explores the directed fragment relationship graph, identifies coherent subsets of fragments
    belonging to the target JPEG, determines the exact fragment sequence through JPEG-aware
    continuation and bitstream parsing, and rejects unrelated decoy fragments.
    """

    @classmethod
    def reconstruct_case(
        cls,
        db: Session,
        case_id: str,
        target_mode: str = "single_jpeg"
    ) -> List[ReconstructionCandidate]:
        """
        Reconstruct JPEG from analyzed fragments and compatibility relationships.
        """
        case = db.query(ForensicCase).filter(ForensicCase.id == case_id).first()
        if not case:
            raise ValueError(f"Case '{case_id}' not found.")

        case.status = "RECONSTRUCTING"
        db.commit()

        fragments = db.query(ForensicFragment).filter(ForensicFragment.case_id == case_id).all()
        if not fragments:
            # Check if original evidence artifacts exist to re-generate temporary analysis dataset on the fly
            artifacts = db.query(ForensicArtifact).filter(ForensicArtifact.case_id == case_id).all()
            if artifacts:
                from app.services.fragment_relationship_service import FragmentRelationshipService
                logger.info(f"Re-analyzing case '{case_id}' fragments and relationships prior to reconstruction...")
                fragments = FragmentRelationshipService.analyze_case_fragments(db, case_id)
                FragmentRelationshipService.compute_case_relationships(db, case_id)
            else:
                cands = db.query(ReconstructionCandidate).filter(ReconstructionCandidate.case_id == case_id).all()
                if cands:
                    case.status = "COMPLETED"
                    db.commit()
                    return cands
                case.status = "FAILED"
                db.commit()
                raise ValueError(f"No evidence artifacts or fragments found for case '{case_id}'.")

        frag_map: Dict[str, ForensicFragment] = {f.id: f for f in fragments}
        num_frags = len(fragments)

        # Single fragment trivial case
        if num_frags == 1:
            f = fragments[0]
            case.status = "VALIDATING"
            db.commit()

            status, integrity_score, val_res = ValidationService.validate_jpeg(f.raw_content)
            val_res["chain_details"] = [{
                "step": 1,
                "fragment_id": f.id,
                "filename": f.source_filename,
                "classification": f.classification,
                "size": f.fragment_size,
                "sha256": f.sha256_hash,
                "next_edge": None
            }]
            val_res["rejected_fragments"] = []
            val_res["ordered_filenames"] = [f.source_filename]
            val_res["selected_fragments_count"] = 1
            val_res["rejected_fragments_count"] = 0
            val_res["temporary_data_cleaned"] = True

            cand = ReconstructionCandidate(
                case_id=case_id,
                file_type="JPEG",
                fragment_order=[f.id],
                fragment_count=1,
                confidence=1.0,
                integrity_score=integrity_score,
                status=status,
                validation_result=val_res,
                reconstructed_size=len(f.raw_content),
                reconstructed_content=f.raw_content
            )
            try:
                # 1. Clear previous candidates
                db.query(ReconstructionCandidate).filter(ReconstructionCandidate.case_id == case_id).delete(synchronize_session=False)

                # 2. Save final reconstruction candidate
                db.add(cand)
                db.flush()

                # 3. Verify candidate was successfully persisted with valid content
                if not cand.id or cand.reconstructed_content is None or len(cand.reconstructed_content) == 0:
                    raise RuntimeError("Failed to verify saved candidate content bytes.")

                # 4. Strict FK order deletion of temporary analysis tables
                db.query(FragmentRelationship).filter(FragmentRelationship.case_id == case_id).delete(synchronize_session=False)
                db.query(ForensicFragment).filter(ForensicFragment.case_id == case_id).delete(synchronize_session=False)
                db.expire(case, ["fragments", "relationships"])

                # 5. Mark case as COMPLETED
                case.status = "COMPLETED"

                # 6. Commit transaction atomically
                db.commit()
                db.refresh(cand)
                logger.info(f"Single-fragment case {case_id} completed. Temporary processing tables purged.")
                return [cand]
            except Exception as exc:
                db.rollback()
                logger.error(f"Single-fragment save/cleanup failed for case {case_id}: {exc}", exc_info=True)
                case.status = "FAILED"
                db.commit()
                raise

        # Fetch pairwise relationships
        relationships = db.query(FragmentRelationship).filter(FragmentRelationship.case_id == case_id).all()
        adj: Dict[str, Dict[str, float]] = {f.id: {} for f in fragments}
        for r in relationships:
            if r.from_fragment_id in adj and r.to_fragment_id in adj:
                adj[r.from_fragment_id][r.to_fragment_id] = r.total_score

        # Identify candidate start, end, and interior fragments
        start_nodes = [f for f in fragments if f.jpeg_features and isinstance(f.jpeg_features, dict) and f.jpeg_features.get("starts_with_soi")]
        end_nodes = {f.id for f in fragments if f.jpeg_features and isinstance(f.jpeg_features, dict) and f.jpeg_features.get("ends_with_eoi")}
        start_node_ids = {f.id for f in start_nodes}

        # Fallback if no explicit SOI found
        if not start_nodes:
            start_nodes = list(fragments)
            start_node_ids = set()

        all_candidate_chains: List[Dict[str, Any]] = []

        # Explore candidate chains starting from each candidate start fragment
        for s_frag in start_nodes:
            d_start = s_frag.raw_content
            sof = (s_frag.jpeg_features.get("sof_info") if isinstance(s_frag.jpeg_features, dict) else None) or JPEGAnalysisService.extract_sof_info(d_start)
            exp_mcus = sof.get("expected_mcus", 0) if isinstance(sof, dict) else 0
            dht = JPEGAnalysisService.extract_dht_tables(d_start)

            # If start fragment has DHT and SOF, use FastJPEGStreamParser
            if dht and exp_mcus > 0:
                sos_idx = d_start.find(b"\xFF\xDA")
                start_offset = 0
                if sos_idx != -1 and sos_idx + 4 < len(d_start):
                    sos_len = (d_start[sos_idx + 2] << 8) | d_start[sos_idx + 3]
                    start_offset = sos_idx + 2 + sos_len

                parser = FastJPEGStreamParser(dht)
                mcu0, res0 = parser.feed(d_start, is_first=True, start_offset=start_offset)
                snap0 = parser.snapshot()

                # Beam search across fragment relationship graph
                beam = [([s_frag.id], snap0, mcu0, 0.0)]
                max_steps = min(num_frags, 20)

                for step in range(1, max_steps + 1):
                    next_beam = []
                    for path, snap, cur_mcu, score in beam:
                        curr_id = path[-1]
                        curr_frag = frag_map.get(curr_id)
                        if not curr_frag:
                            continue
                        used = set(path)
                        t_pat, _ = ScoringService.get_periodic_pattern(curr_frag.raw_content, from_head=False)

                        for next_f in fragments:
                            nid = next_f.id
                            if nid in used or nid in start_node_ids:
                                continue

                            is_end = nid in end_nodes
                            raw_next = next_f.raw_content

                            # Enforce periodic boundary pattern continuity
                            h_pat, _ = ScoringService.get_periodic_pattern(raw_next, from_head=True)
                            if h_pat and h_pat != t_pat:
                                continue
                            if t_pat and h_pat != t_pat:
                                continue

                            # Restore parser state and test candidate continuation
                            parser.restore(snap)
                            mcus, res = parser.feed(raw_next, is_first=False)
                            if "OVERFLOW" in res or "INVALID" in res or mcus > exp_mcus:
                                continue

                            # If end node is reached, verify exact MCU canvas completion
                            if is_end:
                                if mcus == exp_mcus:
                                    full_p = path + [nid]
                                    raw_b = b"".join(frag_map[x].raw_content for x in full_p if x in frag_map)
                                    try:
                                        img = Image.open(io.BytesIO(raw_b))
                                        img.verify()
                                        img2 = Image.open(io.BytesIO(raw_b))
                                        img2.load()
                                        all_candidate_chains.append({
                                            "start_id": s_frag.id,
                                            "path": list(full_p),
                                            "fragment_count": len(full_p),
                                            "bytes": raw_b,
                                            "reconstructed_size": len(raw_b),
                                            "decoded_mcus": mcus,
                                            "expected_mcus": exp_mcus,
                                            "image_size": img2.size,
                                            "sof_info": sof
                                        })
                                    except Exception:
                                        pass
                                continue

                            # Intermediate fragment cannot consume all MCUs before ending fragment
                            if mcus >= exp_mcus:
                                continue

                            edge_score = adj.get(curr_id, {}).get(nid, 0.5)
                            step_score = edge_score
                            if t_pat and h_pat and t_pat == h_pat:
                                step_score += 0.30

                            new_snap = parser.snapshot()
                            next_beam.append((path + [nid], new_snap, mcus, score + step_score))

                    if not next_beam:
                        break

                    # Sort beam by average step compatibility score
                    next_beam.sort(key=lambda x: x[3] / len(x[0]), reverse=True)
                    beam = next_beam[:60]

            else:
                # Fallback graph search for headers without explicit DHT
                beam = [([s_frag.id], 0.0)]
                for step in range(1, num_frags):
                    next_beam = []
                    for path, score in beam:
                        curr_id = path[-1]
                        if curr_id in end_nodes and len(path) > 1:
                            raw_b = b"".join(frag_map[x].raw_content for x in path if x in frag_map)
                            try:
                                img = Image.open(io.BytesIO(raw_b))
                                img.verify()
                                all_candidate_chains.append({
                                    "start_id": s_frag.id,
                                    "path": list(path),
                                    "fragment_count": len(path),
                                    "bytes": raw_b,
                                    "reconstructed_size": len(raw_b),
                                    "decoded_mcus": 0,
                                    "expected_mcus": 0,
                                    "image_size": (0, 0),
                                    "sof_info": sof
                                })
                            except Exception:
                                pass
                            continue

                        used = set(path)
                        for next_id, edge_score in adj.get(curr_id, {}).items():
                            if next_id in used or next_id in start_node_ids:
                                continue
                            next_beam.append((path + [next_id], score + edge_score))

                    if not next_beam:
                        break
                    next_beam.sort(key=lambda x: x[1], reverse=True)
                    beam = next_beam[:20]

        rel_map = {(r.from_fragment_id, r.to_fragment_id): r for r in relationships}

        # Rank all valid candidate chains:
        def score_candidate(cand_dict: Dict[str, Any]) -> float:
            path = cand_dict["path"]
            raw_b = cand_dict["bytes"]

            edge_scores = []
            edge_struct_scores = []
            edge_bound_scores = []
            edge_parser_scores = []
            min_edge = 1.0

            for i in range(len(path) - 1):
                fa = path[i]
                fb = path[i + 1]
                s = adj.get(fa, {}).get(fb, 0.5)
                edge_scores.append(s)
                min_edge = min(min_edge, s)
                r = rel_map.get((fa, fb))
                if r:
                    edge_struct_scores.append(r.structural_score)
                    edge_bound_scores.append(r.boundary_score)
                    edge_parser_scores.append(r.parser_score)
                else:
                    edge_struct_scores.append(s)
                    edge_bound_scores.append(s)
                    edge_parser_scores.append(s)

            avg_edge = sum(edge_scores) / len(edge_scores) if edge_scores else 0.5
            avg_struct = sum(edge_struct_scores) / len(edge_struct_scores) if edge_struct_scores else 0.5
            avg_bound = sum(edge_bound_scores) / len(edge_bound_scores) if edge_bound_scores else 0.5
            avg_parser = sum(edge_parser_scores) / len(edge_parser_scores) if edge_parser_scores else 0.5

            exp_mcu = cand_dict.get("expected_mcus", 0)
            dec_mcu = cand_dict.get("decoded_mcus", 0)

            # MCU canvas accuracy score
            if exp_mcu > 0:
                if dec_mcu == exp_mcu:
                    mcu_score = 100.0
                else:
                    mcu_score = -500.0
            else:
                mcu_score = 0.0

            has_soi_start = raw_b.startswith(b"\xFF\xD8")
            has_eoi_end = raw_b.endswith(b"\xFF\xD9")
            start_end_valid = (1.0 if has_soi_start else 0.0) + (1.0 if has_eoi_end else 0.0)

            # Contradiction penalties:
            soi_cnt = raw_b.count(b"\xFF\xD8")
            eoi_cnt = raw_b.count(b"\xFF\xD9")
            penalties = 0.0
            if soi_cnt > 1:
                penalties += 1000.0 * (soi_cnt - 1)
            if eoi_cnt > 1:
                penalties += 1000.0 * (eoi_cnt - 1)
            if min_edge < 0.40:
                penalties += 250.0  # Weak transition / foreign fragment insertion

            return (
                (avg_edge * 40.0) +
                (avg_struct * 25.0) +
                (avg_bound * 25.0) +
                (avg_parser * 25.0) +
                mcu_score +
                (start_end_valid * 20.0) -
                penalties
            )

        all_candidate_chains.sort(key=score_candidate, reverse=True)

        if not all_candidate_chains:
            case.status = "FAILED"
            db.commit()
            return []

        # Select primary target reconstruction
        primary = all_candidate_chains[0]
        primary_path = primary["path"]
        primary_set = set(primary_path)
        primary_bytes = primary["bytes"]

        case.status = "VALIDATING"
        db.commit()

        # Run multi-stage forensic validation on primary candidate
        status, integrity_score, val_res = ValidationService.validate_jpeg(primary_bytes)

        # Build rejected fragments forensic attribution
        rejected_fragments = []
        for f in fragments:
            if f.id in primary_set:
                continue

            # Determine specific forensic rejection reason
            f_starts_soi = f.jpeg_features and isinstance(f.jpeg_features, dict) and f.jpeg_features.get("starts_with_soi")
            f_ends_eoi = f.jpeg_features and isinstance(f.jpeg_features, dict) and f.jpeg_features.get("ends_with_eoi")
            f_sof = f.jpeg_features.get("sof_info") if isinstance(f.jpeg_features, dict) else None

            reasons = []
            if f_starts_soi:
                target_sof = primary.get("sof_info") or {}
                t_w, t_h = (target_sof.get("width", "?"), target_sof.get("height", "?")) if isinstance(target_sof, dict) else ("?", "?")
                w = (f_sof.get("width", "?"), f_sof.get("height", "?"))[0] if isinstance(f_sof, dict) else "?"
                h = (f_sof.get("width", "?"), f_sof.get("height", "?"))[1] if isinstance(f_sof, dict) else "?"
                reasons.append(f"Competing JPEG structure: Separate SOI header detected (declared {w}x{h} vs target {t_w}x{t_h})")
                reasons.append("Creates fatal internal SOI conflict if merged into target chain")
            elif f_ends_eoi:
                reasons.append("Competing JPEG structure: Separate EOI file terminator detected")
                reasons.append("Incompatible scan continuation: Causes premature bitstream termination or MCU count mismatch")
            else:
                reasons.append("Low global path compatibility: Incompatible entropy-coded data with target stream")
                reasons.append("Creates invalid continuation / bitstream desynchronization")

            rejected_fragments.append({
                "fragment_id": f.id,
                "filename": f.source_filename,
                "classification": f.classification,
                "size": f.fragment_size,
                "sha256": f.sha256_hash,
                "reason": " • ".join(reasons)
            })

        # Build chain details with fragment metadata and directed edge scores BEFORE temporary table deletion
        chain_details = []
        for i, fid in enumerate(primary_path):
            f = frag_map.get(fid)
            next_edge_info = None
            if i < len(primary_path) - 1:
                next_fid = primary_path[i + 1]
                edge = rel_map.get((fid, next_fid))
                if edge:
                    next_edge_info = {
                        "to_fragment_id": next_fid,
                        "to_filename": frag_map[next_fid].source_filename if next_fid in frag_map else "Unknown",
                        "total_score": edge.total_score,
                        "structural_score": edge.structural_score,
                        "boundary_score": edge.boundary_score,
                        "parser_score": edge.parser_score,
                        "evidence": edge.evidence
                    }

            chain_details.append({
                "step": i + 1,
                "fragment_id": fid,
                "filename": f.source_filename if f else "Unknown",
                "classification": f.classification if f else "Unknown",
                "size": f.fragment_size if f else 0,
                "sha256": f.sha256_hash if f else "",
                "next_edge": next_edge_info
            })

        val_res["chain_details"] = chain_details
        val_res["rejected_fragments"] = rejected_fragments
        val_res["ordered_filenames"] = [frag_map[fid].source_filename for fid in primary_path if fid in frag_map]
        val_res["selected_fragments_count"] = len(primary_path)
        val_res["rejected_fragments_count"] = len(rejected_fragments)
        val_res["temporary_data_cleaned"] = True

        # Compute calibrated confidence score
        edge_scores = [adj.get(primary_path[i], {}).get(primary_path[i + 1], 0.7) for i in range(len(primary_path) - 1)]
        avg_edge_score = sum(edge_scores) / len(edge_scores) if edge_scores else 0.7

        mcu_completion = 1.0 if primary.get("expected_mcus", 0) > 0 and primary.get("decoded_mcus") == primary.get("expected_mcus") else 0.8
        is_clean_decode = 1.0 if val_res.get("decoder_valid") and val_res.get("structurally_parseable") else 0.5
        no_marker_violations = 1.0 if not val_res.get("has_internal_soi") and not val_res.get("has_internal_eoi") else 0.1

        confidence = round(
            (avg_edge_score * 0.35 + mcu_completion * 0.30 + is_clean_decode * 0.25 + no_marker_violations * 0.10),
            4
        )

        cand = ReconstructionCandidate(
            case_id=case_id,
            file_type="JPEG",
            fragment_order=primary_path,
            fragment_count=len(primary_path),
            confidence=confidence,
            integrity_score=integrity_score,
            status=status,
            validation_result=val_res,
            reconstructed_size=len(primary_bytes),
            reconstructed_content=primary_bytes
        )

        try:
            # 1. Clear previous candidates for this case
            db.query(ReconstructionCandidate).filter(ReconstructionCandidate.case_id == case_id).delete(synchronize_session=False)

            # 2. Save final reconstruction candidate
            db.add(cand)
            db.flush()

            # 3. Verify candidate was successfully persisted with valid content
            if not cand.id or cand.reconstructed_content is None or len(cand.reconstructed_content) == 0:
                raise RuntimeError("Failed to verify saved candidate content bytes.")

            # 4. Strict FK order deletion of temporary analysis tables
            db.query(FragmentRelationship).filter(FragmentRelationship.case_id == case_id).delete(synchronize_session=False)
            db.query(ForensicFragment).filter(ForensicFragment.case_id == case_id).delete(synchronize_session=False)
            db.expire(case, ["fragments", "relationships"])

            # 5. Mark case as COMPLETED
            case.status = "COMPLETED"

            # 6. Commit transaction atomically
            db.commit()
            db.refresh(cand)

            logger.info(
                f"Case {case_id} reconstructed: {len(primary_path)} fragments, "
                f"{len(primary_bytes)} bytes, status={status}, confidence={confidence:.1%}. "
                f"Temporary processing records (fragments, relationships) purged."
            )

            return [cand]

        except Exception as exc:
            db.rollback()
            logger.error(f"Reconstruction save/cleanup failed for case {case_id}: {exc}", exc_info=True)
            # Preserve temporary analysis data for debugging
            case.status = "FAILED"
            db.commit()
            raise
