import uuid
from datetime import datetime
from sqlalchemy import Column, String, BigInteger, Boolean, DateTime, ForeignKey, LargeBinary, Text, Integer, Float, JSON
from sqlalchemy.orm import relationship
from app.db.database import Base

def generate_case_id():
    return f"CASE-{uuid.uuid4().hex[:8].upper()}"

def generate_uuid():
    return str(uuid.uuid4())

class ForensicCase(Base):
    __tablename__ = "forensic_cases"

    id = Column(String(50), primary_key=True, default=generate_case_id)
    case_name = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String(50), default="UPLOADED")
    total_files = Column(BigInteger, default=0)
    total_size = Column(BigInteger, default=0)

    artifacts = relationship("ForensicArtifact", back_populates="case", cascade="all, delete-orphan")
    fragments = relationship("ForensicFragment", back_populates="case", cascade="all, delete-orphan")
    relationships = relationship("FragmentRelationship", back_populates="case", cascade="all, delete-orphan")
    reconstructions = relationship("ReconstructionCandidate", back_populates="case", cascade="all, delete-orphan")

class ForensicArtifact(Base):
    __tablename__ = "forensic_artifacts"

    id = Column(String(50), primary_key=True, default=generate_uuid)
    case_id = Column(String(50), ForeignKey("forensic_cases.id", ondelete="CASCADE"), nullable=False, index=True)
    original_filename = Column(String(255), nullable=False)
    relative_path = Column(Text, nullable=False)
    file_extension = Column(String(50), nullable=True)
    mime_type = Column(String(100), nullable=True)
    file_size = Column(BigInteger, nullable=False)
    sha256_hash = Column(String(64), nullable=False, index=True)
    magic_signature = Column(String(100), nullable=True)
    is_duplicate = Column(Boolean, default=False)
    content = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    case = relationship("ForensicCase", back_populates="artifacts")
    fragment = relationship("ForensicFragment", back_populates="artifact", uselist=False)

class ForensicFragment(Base):
    __tablename__ = "forensic_fragments"

    id = Column(String(50), primary_key=True, default=generate_uuid)
    case_id = Column(String(50), ForeignKey("forensic_cases.id", ondelete="CASCADE"), nullable=False, index=True)
    artifact_id = Column(String(50), ForeignKey("forensic_artifacts.id", ondelete="SET NULL"), nullable=True, index=True)

    fragment_index = Column(Integer, default=0)
    source_filename = Column(Text, nullable=False)
    relative_path = Column(Text, nullable=False)

    start_offset = Column(BigInteger, nullable=True)
    end_offset = Column(BigInteger, nullable=True)
    fragment_size = Column(BigInteger, nullable=False)

    sha256_hash = Column(String(64), nullable=False, index=True)
    detected_file_type = Column(String(50), default="JPEG")
    detected_format_confidence = Column(Float, default=1.0)
    classification = Column(String(50), default="UNKNOWN_JPEG_FRAGMENT")

    raw_content = Column(LargeBinary, nullable=False)

    jpeg_markers = Column(JSON, nullable=True)
    jpeg_features = Column(JSON, nullable=True)

    entropy = Column(Float, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    case = relationship("ForensicCase", back_populates="fragments")
    artifact = relationship("ForensicArtifact", back_populates="fragment")

class FragmentRelationship(Base):
    __tablename__ = "fragment_relationships"

    id = Column(String(50), primary_key=True, default=generate_uuid)
    case_id = Column(String(50), ForeignKey("forensic_cases.id", ondelete="CASCADE"), nullable=False, index=True)

    from_fragment_id = Column(String(50), ForeignKey("forensic_fragments.id", ondelete="CASCADE"), nullable=False, index=True)
    to_fragment_id = Column(String(50), ForeignKey("forensic_fragments.id", ondelete="CASCADE"), nullable=False, index=True)

    physical_score = Column(Float, nullable=True)
    structural_score = Column(Float, default=0.0)
    boundary_score = Column(Float, default=0.0)
    parser_score = Column(Float, default=0.0)
    ml_score = Column(Float, nullable=True)

    total_score = Column(Float, default=0.0)

    evidence = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    case = relationship("ForensicCase", back_populates="relationships")
    from_fragment = relationship("ForensicFragment", foreign_keys=[from_fragment_id])
    to_fragment = relationship("ForensicFragment", foreign_keys=[to_fragment_id])

class ReconstructionCandidate(Base):
    __tablename__ = "reconstruction_candidates"

    id = Column(String(50), primary_key=True, default=generate_uuid)
    case_id = Column(String(50), ForeignKey("forensic_cases.id", ondelete="CASCADE"), nullable=False, index=True)

    file_type = Column(String(50), default="JPEG")
    fragment_order = Column(JSON, nullable=False)
    fragment_count = Column(Integer, default=0)

    confidence = Column(Float, default=0.0)
    integrity_score = Column(Float, default=0.0)
    status = Column(String(50), default="PENDING")

    validation_result = Column(JSON, nullable=True)
    reconstructed_size = Column(BigInteger, default=0)
    reconstructed_content = Column(LargeBinary, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    case = relationship("ForensicCase", back_populates="reconstructions")
