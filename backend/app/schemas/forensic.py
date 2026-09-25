from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict

class ArtifactSummary(BaseModel):
    artifact_id: str
    filename: str
    relative_path: str
    file_extension: Optional[str] = None
    mime_type: Optional[str] = None
    size: int
    sha256: str
    magic_signature: Optional[str] = None
    is_duplicate: bool = False
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class UploadResponse(BaseModel):
    case_id: str
    case_name: str
    files_uploaded: int
    total_size: int
    status: str
    created_at: datetime
    artifacts: List[ArtifactSummary]

    model_config = ConfigDict(from_attributes=True)

class CaseDetailResponse(BaseModel):
    case_id: str
    case_name: str
    status: str
    created_at: datetime
    total_files: int
    total_size: int
    artifacts: List[ArtifactSummary]

    model_config = ConfigDict(from_attributes=True)

class FragmentSummary(BaseModel):
    id: str
    case_id: str
    artifact_id: Optional[str] = None
    fragment_index: int
    source_filename: str
    relative_path: str
    fragment_size: int
    sha256_hash: str
    detected_file_type: str
    detected_format_confidence: float
    classification: str
    jpeg_markers: Optional[List[dict]] = None
    jpeg_features: Optional[dict] = None
    entropy: Optional[float] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class RelationshipSummary(BaseModel):
    id: str
    case_id: str
    from_fragment_id: str
    to_fragment_id: str
    from_filename: Optional[str] = None
    to_filename: Optional[str] = None
    physical_score: Optional[float] = None
    structural_score: float
    boundary_score: float
    parser_score: float
    ml_score: Optional[float] = None
    total_score: float
    evidence: Optional[dict] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class ReconstructionSummary(BaseModel):
    id: str
    case_id: str
    file_type: str
    fragment_order: List[str]
    fragment_count: int
    confidence: float
    integrity_score: float
    status: str
    validation_result: Optional[dict] = None
    reconstructed_size: int
    created_at: datetime
    chain_details: Optional[List[dict]] = None
    rejected_fragments: Optional[List[dict]] = None

    model_config = ConfigDict(from_attributes=True)

class AnalysisResponse(BaseModel):
    case_id: str
    status: str
    total_fragments: int
    fragments: List[FragmentSummary]
    total_relationships: int
    relationships: List[RelationshipSummary]

    model_config = ConfigDict(from_attributes=True)

