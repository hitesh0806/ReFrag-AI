import logging
from typing import List, Dict, Any
from sqlalchemy.orm import Session

from app.models.forensic import ForensicCase, ForensicArtifact, ForensicFragment, FragmentRelationship
from app.services.jpeg_analysis_service import JPEGAnalysisService
from app.services.scoring_service import ScoringService

logger = logging.getLogger("refrag_ai.relationships")

class FragmentRelationshipService:
    """
    Orchestrates fragment detection, feature extraction, and pairwise compatibility graph generation.
    """

    @classmethod
    def analyze_case_fragments(cls, db: Session, case_id: str) -> List[ForensicFragment]:
        """
        Extract forensic features and structural classification for each artifact in the case.
        """
        case = db.query(ForensicCase).filter(ForensicCase.id == case_id).first()
        if not case:
            raise ValueError(f"Case '{case_id}' not found.")

        case.status = "ANALYZING"
        db.commit()

        # Repeated analysis guard: delete previous temporary processing tables in strict FK order
        db.query(FragmentRelationship).filter(FragmentRelationship.case_id == case_id).delete(synchronize_session=False)
        db.query(ForensicFragment).filter(ForensicFragment.case_id == case_id).delete(synchronize_session=False)
        db.expire(case, ["fragments", "relationships"])
        db.flush()

        artifacts = db.query(ForensicArtifact).filter(ForensicArtifact.case_id == case_id).all()
        if not artifacts:
            case.status = "FAILED"
            db.commit()
            raise ValueError(f"No artifacts found in case '{case_id}'.")

        fragments: List[ForensicFragment] = []

        for idx, art in enumerate(artifacts):
            features_result = JPEGAnalysisService.extract_features(art.content)

            frag = ForensicFragment(
                case_id=case_id,
                artifact_id=art.id,
                fragment_index=idx,
                source_filename=art.original_filename,
                relative_path=art.relative_path,
                start_offset=None,
                end_offset=None,
                fragment_size=art.file_size,
                sha256_hash=art.sha256_hash,
                detected_file_type="JPEG",
                detected_format_confidence=features_result["format_confidence"],
                classification=features_result["classification"],
                raw_content=art.content,
                jpeg_markers=features_result["markers"],
                jpeg_features=features_result["features"],
                entropy=features_result["entropy"],
            )
            db.add(frag)
            fragments.append(frag)

        case.status = "ANALYZING"
        db.commit()

        for f in fragments:
            db.refresh(f)

        return fragments

    @classmethod
    def compute_case_relationships(cls, db: Session, case_id: str) -> List[FragmentRelationship]:
        """
        Evaluate pairwise compatibility scores for all directed pairs A -> B in the case.
        """
        case = db.query(ForensicCase).filter(ForensicCase.id == case_id).first()
        if not case:
            raise ValueError(f"Case '{case_id}' not found.")

        # Ensure fragments are analyzed
        fragments = db.query(ForensicFragment).filter(ForensicFragment.case_id == case_id).all()
        if not fragments:
            fragments = cls.analyze_case_fragments(db, case_id)

        # Remove stale relationships for this case
        db.query(FragmentRelationship).filter(FragmentRelationship.case_id == case_id).delete(synchronize_session=False)
        db.flush()

        relationships: List[FragmentRelationship] = []

        # Convert fragments to lookup dict for rapid access
        frag_data_map = {}
        for f in fragments:
            frag_data_map[f.id] = {
                "id": f.id,
                "start_offset": f.start_offset,
                "end_offset": f.end_offset,
                "classification": f.classification,
                "jpeg_features": f.jpeg_features or {},
                "jpeg_markers": f.jpeg_markers or [],
                "raw_content": f.raw_content,
                "source_filename": f.source_filename,
            }

        # Calculate directed scores for all pairs A -> B
        for f_a in fragments:
            for f_b in fragments:
                if f_a.id == f_b.id:
                    continue

                d_a = frag_data_map[f_a.id]
                d_b = frag_data_map[f_b.id]

                score_info = ScoringService.calculate_total_score(
                    from_frag=d_a,
                    to_frag=d_b,
                    raw_a=d_a["raw_content"],
                    raw_b=d_b["raw_content"],
                )

                rel = FragmentRelationship(
                    case_id=case_id,
                    from_fragment_id=f_a.id,
                    to_fragment_id=f_b.id,
                    physical_score=score_info["physical_score"],
                    structural_score=score_info["structural_score"],
                    boundary_score=score_info["boundary_score"],
                    parser_score=score_info["parser_score"],
                    ml_score=score_info["ml_score"],
                    total_score=score_info["total_score"],
                    evidence=score_info["evidence"],
                )
                db.add(rel)
                relationships.append(rel)

        case.status = "ANALYZING"
        db.commit()

        for r in relationships:
            db.refresh(r)

        return relationships
