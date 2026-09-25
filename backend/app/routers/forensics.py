from typing import List, Optional
from fastapi import APIRouter, Depends, Form, UploadFile, Response, status, HTTPException
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.schemas.forensic import (
    UploadResponse,
    CaseDetailResponse,
    ArtifactSummary,
    FragmentSummary,
    RelationshipSummary,
    ReconstructionSummary,
    AnalysisResponse,
)
from app.services.forensic_service import ForensicService

router = APIRouter(prefix="/api/forensics", tags=["Forensic Ingestion"])

@router.post("/upload", response_model=UploadResponse, status_code=status.HTTP_201_CREATED)
async def upload_forensic_dataset(
    files: List[UploadFile],
    relative_paths: Optional[List[str]] = Form(None),
    case_name: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    """
    Ingest forensic artifacts (files or directory structures).
    Calculates SHA-256, extracts file signatures, and persists exact bytes into database.
    """
    return await ForensicService.process_upload(
        db=db,
        files=files,
        relative_paths=relative_paths,
        case_name=case_name
    )

@router.get("/cases/{case_id}", response_model=CaseDetailResponse)
def get_case_details(case_id: str, db: Session = Depends(get_db)):
    """
    Retrieve forensic case summary and artifact metadata list.
    """
    return ForensicService.get_case_detail(db=db, case_id=case_id)

@router.get("/artifacts/{artifact_id}", response_model=ArtifactSummary)
def get_artifact_details(artifact_id: str, db: Session = Depends(get_db)):
    """
    Retrieve metadata for a specific forensic artifact.
    """
    art = ForensicService.get_artifact(db=db, artifact_id=artifact_id)
    return ArtifactSummary(
        artifact_id=art.id,
        filename=art.original_filename,
        relative_path=art.relative_path,
        file_extension=art.file_extension,
        mime_type=art.mime_type,
        size=art.file_size,
        sha256=art.sha256_hash,
        magic_signature=art.magic_signature,
        is_duplicate=art.is_duplicate,
        created_at=art.created_at
    )

@router.get("/artifacts/{artifact_id}/download")
def download_artifact(artifact_id: str, db: Session = Depends(get_db)):
    """
    Download/retrieve raw binary bytes of a stored artifact for integrity verification.
    """
    art = ForensicService.get_artifact(db=db, artifact_id=artifact_id)
    return Response(
        content=art.content,
        media_type=art.mime_type or "application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{art.original_filename}"',
            "X-SHA256-Hash": art.sha256_hash
        }
    )

@router.post("/cases/{case_id}/analyze", response_model=AnalysisResponse)
def analyze_case_fragments(case_id: str, db: Session = Depends(get_db)):
    """
    Trigger JPEG fragment detection, structural feature extraction,
    and pairwise compatibility relationship graph generation.
    """
    from app.services.fragment_relationship_service import FragmentRelationshipService
    from app.models.forensic import ForensicCase, ForensicFragment, FragmentRelationship

    case = db.query(ForensicCase).filter(ForensicCase.id == case_id).first()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_id}' not found.")

    fragments = FragmentRelationshipService.analyze_case_fragments(db=db, case_id=case_id)
    relationships = FragmentRelationshipService.compute_case_relationships(db=db, case_id=case_id)

    frag_name_map = {f.id: f.source_filename for f in fragments}

    frag_summaries = [
        FragmentSummary(
            id=f.id,
            case_id=f.case_id,
            artifact_id=f.artifact_id,
            fragment_index=f.fragment_index,
            source_filename=f.source_filename,
            relative_path=f.relative_path,
            fragment_size=f.fragment_size,
            sha256_hash=f.sha256_hash,
            detected_file_type=f.detected_file_type,
            detected_format_confidence=f.detected_format_confidence,
            classification=f.classification,
            jpeg_markers=f.jpeg_markers,
            jpeg_features=f.jpeg_features,
            entropy=f.entropy,
            created_at=f.created_at
        )
        for f in fragments
    ]

    rel_summaries = [
        RelationshipSummary(
            id=r.id,
            case_id=r.case_id,
            from_fragment_id=r.from_fragment_id,
            to_fragment_id=r.to_fragment_id,
            from_filename=frag_name_map.get(r.from_fragment_id),
            to_filename=frag_name_map.get(r.to_fragment_id),
            physical_score=r.physical_score,
            structural_score=r.structural_score,
            boundary_score=r.boundary_score,
            parser_score=r.parser_score,
            ml_score=r.ml_score,
            total_score=r.total_score,
            evidence=r.evidence,
            created_at=r.created_at
        )
        for r in relationships
    ]

    return AnalysisResponse(
        case_id=case_id,
        status=case.status,
        total_fragments=len(frag_summaries),
        fragments=frag_summaries,
        total_relationships=len(rel_summaries),
        relationships=rel_summaries
    )

def build_reconstruction_summary(cand, db: Session) -> ReconstructionSummary:
    val_res = cand.validation_result or {}
    chain_details = val_res.get("chain_details")

    # If chain_details wasn't stored in validation_result (e.g. legacy candidates), build from DB
    if not chain_details:
        from app.models.forensic import ForensicFragment, FragmentRelationship, ForensicArtifact
        fragments = db.query(ForensicFragment).filter(ForensicFragment.case_id == cand.case_id).all()
        frag_map = {f.id: f for f in fragments}
        relationships = db.query(FragmentRelationship).filter(FragmentRelationship.case_id == cand.case_id).all()
        rel_map = {(r.from_fragment_id, r.to_fragment_id): r for r in relationships}

        # If fragments were purged, try matching artifacts as fallback
        artifacts = db.query(ForensicArtifact).filter(ForensicArtifact.case_id == cand.case_id).all()
        art_map = {a.id: a for a in artifacts}

        order = cand.fragment_order or []
        chain_details = []
        for i, fid in enumerate(order):
            f = frag_map.get(fid)
            next_edge_info = None
            if i < len(order) - 1:
                next_fid = order[i + 1]
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
                "filename": f.source_filename if f else (art_map[fid].original_filename if fid in art_map else f"Fragment {i+1}"),
                "classification": f.classification if f else "RECONSTRUCTED_MEMBER",
                "size": f.fragment_size if f else (art_map[fid].file_size if fid in art_map else 0),
                "sha256": f.sha256_hash if f else (art_map[fid].sha256_hash if fid in art_map else ""),
                "next_edge": next_edge_info
            })

    rejected = val_res.get("rejected_fragments", [])

    return ReconstructionSummary(
        id=cand.id,
        case_id=cand.case_id,
        file_type=cand.file_type,
        fragment_order=cand.fragment_order,
        fragment_count=cand.fragment_count,
        confidence=cand.confidence,
        integrity_score=cand.integrity_score,
        status=cand.status,
        validation_result=cand.validation_result,
        reconstructed_size=cand.reconstructed_size,
        created_at=cand.created_at,
        chain_details=chain_details,
        rejected_fragments=rejected
    )

@router.post("/cases/{case_id}/reconstruct", response_model=List[ReconstructionSummary])
def reconstruct_case(case_id: str, db: Session = Depends(get_db)):
    """
    Execute JPEG fragment chain reconstruction and multi-stage decoder validation.
    Saves final candidate and purges temporary processing tables (fragments & relationships).
    """
    from app.services.reconstruction_service import ReconstructionService
    from app.models.forensic import ForensicCase

    case = db.query(ForensicCase).filter(ForensicCase.id == case_id).first()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_id}' not found.")

    candidates = ReconstructionService.reconstruct_case(db=db, case_id=case_id)
    return [build_reconstruction_summary(cand, db) for cand in candidates]

@router.get("/cases/{case_id}/fragments", response_model=List[FragmentSummary])
def get_case_fragments(case_id: str, db: Session = Depends(get_db)):
    """
    Retrieve all analyzed fragments for a given forensic case.
    Returns empty list if temporary analysis data has already been purged upon completion.
    """
    from app.models.forensic import ForensicFragment
    fragments = db.query(ForensicFragment).filter(
        ForensicFragment.case_id == case_id
    ).order_by(ForensicFragment.fragment_index.asc()).all()

    return [
        FragmentSummary(
            id=f.id,
            case_id=f.case_id,
            artifact_id=f.artifact_id,
            fragment_index=f.fragment_index,
            source_filename=f.source_filename,
            relative_path=f.relative_path,
            fragment_size=f.fragment_size,
            sha256_hash=f.sha256_hash,
            detected_file_type=f.detected_file_type,
            detected_format_confidence=f.detected_format_confidence,
            classification=f.classification,
            jpeg_markers=f.jpeg_markers,
            jpeg_features=f.jpeg_features,
            entropy=f.entropy,
            created_at=f.created_at
        )
        for f in fragments
    ]

@router.get("/cases/{case_id}/relationships", response_model=List[RelationshipSummary])
def get_case_relationships(case_id: str, db: Session = Depends(get_db)):
    """
    Retrieve all directed pairwise fragment relationships for a given forensic case.
    Returns empty list if temporary analysis data has already been purged upon completion.
    """
    from app.models.forensic import FragmentRelationship, ForensicFragment
    relationships = db.query(FragmentRelationship).filter(
        FragmentRelationship.case_id == case_id
    ).order_by(FragmentRelationship.total_score.desc()).all()

    fragments = db.query(ForensicFragment).filter(ForensicFragment.case_id == case_id).all()
    frag_name_map = {f.id: f.source_filename for f in fragments}

    return [
        RelationshipSummary(
            id=r.id,
            case_id=r.case_id,
            from_fragment_id=r.from_fragment_id,
            to_fragment_id=r.to_fragment_id,
            from_filename=frag_name_map.get(r.from_fragment_id),
            to_filename=frag_name_map.get(r.to_fragment_id),
            physical_score=r.physical_score,
            structural_score=r.structural_score,
            boundary_score=r.boundary_score,
            parser_score=r.parser_score,
            ml_score=r.ml_score,
            total_score=r.total_score,
            evidence=r.evidence,
            created_at=r.created_at
        )
        for r in relationships
    ]

@router.get("/cases/{case_id}/reconstructions", response_model=List[ReconstructionSummary])
def get_case_reconstructions(case_id: str, db: Session = Depends(get_db)):
    """
    Retrieve all reconstruction candidates for a given forensic case.
    Retains full chain details and verification metrics even after temporary data is purged.
    """
    from app.models.forensic import ReconstructionCandidate
    candidates = db.query(ReconstructionCandidate).filter(
        ReconstructionCandidate.case_id == case_id
    ).order_by(ReconstructionCandidate.created_at.desc()).all()

    return [build_reconstruction_summary(cand, db) for cand in candidates]

@router.get("/reconstructions/{reconstruction_id}", response_model=ReconstructionSummary)
def get_reconstruction_details(reconstruction_id: str, db: Session = Depends(get_db)):
    """
    Retrieve specific reconstruction candidate by ID with chain details.
    """
    from app.models.forensic import ReconstructionCandidate
    cand = db.query(ReconstructionCandidate).filter(
        ReconstructionCandidate.id == reconstruction_id
    ).first()
    if not cand:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Reconstruction not found.")

    return build_reconstruction_summary(cand, db)

@router.get("/reconstructions/{reconstruction_id}/download")
def download_reconstructed_jpeg(reconstruction_id: str, db: Session = Depends(get_db)):
    """
    Download the reconstructed JPEG image file.
    """
    from app.models.forensic import ReconstructionCandidate
    cand = db.query(ReconstructionCandidate).filter(
        ReconstructionCandidate.id == reconstruction_id
    ).first()
    if not cand or not cand.reconstructed_content:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Reconstruction content not available.")

    filename = f"reconstructed_{cand.case_id}_{cand.id[:8]}.jpg"
    return Response(
        content=cand.reconstructed_content,
        media_type="image/jpeg",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Reconstruction-Confidence": str(cand.confidence),
            "X-Reconstruction-Status": cand.status,
        }
    )

@router.get("/reconstructions/{reconstruction_id}/view")
def view_reconstructed_jpeg(reconstruction_id: str, db: Session = Depends(get_db)):
    """
    Serve the reconstructed JPEG inline for browser rendering.
    """
    from app.models.forensic import ReconstructionCandidate
    cand = db.query(ReconstructionCandidate).filter(
        ReconstructionCandidate.id == reconstruction_id
    ).first()
    if not cand or not cand.reconstructed_content:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Reconstruction content not available.")

    return Response(
        content=cand.reconstructed_content,
        media_type="image/jpeg",
        headers={
            "Cache-Control": "no-cache",
            "Content-Type": "image/jpeg",
        }
    )

@router.delete("/cases/{case_id}/temporary-data")
def cleanup_case_temporary_data(case_id: str, db: Session = Depends(get_db)):
    """
    DEVELOPMENT/ADMIN ONLY:
    Safely delete temporary processing data (fragment_relationships, forensic_fragments)
    for a specified case_id.
    IMPORTANT: NEVER deletes original evidence (forensic_cases, forensic_artifacts)
    or completed reconstruction results (reconstruction_candidates).
    """
    from app.models.forensic import ForensicCase, ForensicFragment, FragmentRelationship

    case = db.query(ForensicCase).filter(ForensicCase.id == case_id).first()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_id}' not found.")

    # Strict foreign key deletion order:
    # 1. fragment_relationships first (foreign key to forensic_fragments)
    deleted_relationships = db.query(FragmentRelationship).filter(
        FragmentRelationship.case_id == case_id
    ).delete(synchronize_session=False)

    # 2. forensic_fragments second
    deleted_fragments = db.query(ForensicFragment).filter(
        ForensicFragment.case_id == case_id
    ).delete(synchronize_session=False)

    db.expire(case, ["fragments", "relationships"])
    db.commit()

    return {
        "status": "success",
        "case_id": case_id,
        "deleted_relationships": deleted_relationships,
        "deleted_fragments": deleted_fragments,
        "message": "Temporary analysis data cleaned successfully."
    }

@router.delete("/temporary-data/cleanup-completed")
def cleanup_all_completed_cases_temporary_data(db: Session = Depends(get_db)):
    """
    DEVELOPMENT/ADMIN ONLY:
    Safely purges temporary processing records for all cases with status 'COMPLETED'.
    Does NOT delete cases, artifacts, or candidates.
    """
    from app.models.forensic import ForensicCase, ForensicFragment, FragmentRelationship

    completed_cases = db.query(ForensicCase.id).filter(ForensicCase.status == "COMPLETED").all()
    completed_case_ids = [c[0] for c in completed_cases]

    if not completed_case_ids:
        return {
            "status": "success",
            "cleaned_cases_count": 0,
            "deleted_relationships": 0,
            "deleted_fragments": 0,
            "message": "No completed cases found requiring temporary data cleanup."
        }

    deleted_relationships = db.query(FragmentRelationship).filter(
        FragmentRelationship.case_id.in_(completed_case_ids)
    ).delete(synchronize_session=False)

    deleted_fragments = db.query(ForensicFragment).filter(
        ForensicFragment.case_id.in_(completed_case_ids)
    ).delete(synchronize_session=False)

    db.commit()

    return {
        "status": "success",
        "cleaned_cases_count": len(completed_case_ids),
        "deleted_relationships": deleted_relationships,
        "deleted_fragments": deleted_fragments,
        "message": f"Purged temporary analysis data for {len(completed_case_ids)} completed cases."
    }

