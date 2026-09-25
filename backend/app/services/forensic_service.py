from typing import List, Optional
from datetime import datetime
from fastapi import HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.models.forensic import ForensicCase, ForensicArtifact
from app.schemas.forensic import UploadResponse, ArtifactSummary, CaseDetailResponse
from app.utils.hashing import calculate_sha256
from app.utils.magic import detect_file_signature
from app.utils.sanitization import sanitize_filename, sanitize_relative_path, get_file_extension
from app.config import settings

class ForensicService:

    @staticmethod
    async def process_upload(
        db: Session,
        files: List[UploadFile],
        relative_paths: Optional[List[str]] = None,
        case_name: Optional[str] = None
    ) -> UploadResponse:
        if not files or len(files) == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No files provided for ingestion."
            )

        max_size_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024

        # Generate case name if missing
        if not case_name or case_name.strip() == "":
            case_name = f"Forensic Case - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"

        # Create new forensic case
        new_case = ForensicCase(
            case_name=case_name,
            status="UPLOADED",
            total_files=0,
            total_size=0
        )
        db.add(new_case)
        db.flush()  # Generates new_case.id

        artifact_responses: List[ArtifactSummary] = []
        total_size_acc = 0

        for idx, file in enumerate(files):
            # Read exact raw bytes
            content = await file.read()
            file_size = len(content)

            if file_size > max_size_bytes:
                db.rollback()
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"File '{file.filename}' exceeds maximum allowed upload size ({settings.MAX_UPLOAD_SIZE_MB}MB)."
                )

            # Extract relative path if provided
            rel_path_raw = relative_paths[idx] if relative_paths and idx < len(relative_paths) else file.filename
            clean_rel_path = sanitize_relative_path(rel_path_raw, file.filename)
            clean_filename = sanitize_filename(file.filename)
            ext = get_file_extension(clean_filename)

            # Calculate SHA-256 on exact raw bytes
            sha256_hash = calculate_sha256(content)

            # Detect magic signature & MIME type
            magic_sig, detected_mime = detect_file_signature(content, file.content_type, clean_filename)

            # Check duplicate artifact in DB by hash
            existing = db.query(ForensicArtifact).filter(ForensicArtifact.sha256_hash == sha256_hash).first()
            is_dup = existing is not None

            # Create artifact model
            artifact = ForensicArtifact(
                case_id=new_case.id,
                original_filename=clean_filename,
                relative_path=clean_rel_path,
                file_extension=ext,
                mime_type=detected_mime,
                file_size=file_size,
                sha256_hash=sha256_hash,
                magic_signature=magic_sig,
                is_duplicate=is_dup,
                content=content
            )

            db.add(artifact)
            db.flush()

            total_size_acc += file_size

            artifact_responses.append(
                ArtifactSummary(
                    artifact_id=artifact.id,
                    filename=clean_filename,
                    relative_path=clean_rel_path,
                    file_extension=ext,
                    mime_type=detected_mime,
                    size=file_size,
                    sha256=sha256_hash,
                    magic_signature=magic_sig,
                    is_duplicate=is_dup,
                    created_at=artifact.created_at
                )
            )

        new_case.total_files = len(files)
        new_case.total_size = total_size_acc
        db.commit()
        db.refresh(new_case)

        return UploadResponse(
            case_id=new_case.id,
            case_name=new_case.case_name,
            files_uploaded=new_case.total_files,
            total_size=new_case.total_size,
            status=new_case.status,
            created_at=new_case.created_at,
            artifacts=artifact_responses
        )

    @staticmethod
    def get_case_detail(db: Session, case_id: str) -> CaseDetailResponse:
        case = db.query(ForensicCase).filter(ForensicCase.id == case_id).first()
        if not case:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Forensic case '{case_id}' not found."
            )

        artifacts_summary = [
            ArtifactSummary(
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
            for art in case.artifacts
        ]

        return CaseDetailResponse(
            case_id=case.id,
            case_name=case.case_name,
            status=case.status,
            created_at=case.created_at,
            total_files=case.total_files,
            total_size=case.total_size,
            artifacts=artifacts_summary
        )

    @staticmethod
    def get_artifact(db: Session, artifact_id: str) -> ForensicArtifact:
        artifact = db.query(ForensicArtifact).filter(ForensicArtifact.id == artifact_id).first()
        if not artifact:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Artifact '{artifact_id}' not found."
            )
        return artifact
