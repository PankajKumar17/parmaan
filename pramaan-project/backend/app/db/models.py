from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import JSON, Boolean, CheckConstraint, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid4()))
    email: Mapped[str] = mapped_column(String, unique=True)
    hashed_password: Mapped[str] = mapped_column(String)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        CheckConstraint(
            "asset_type IN ('DATASET', 'MODEL', 'CONTRIBUTOR')",
            name="ck_assets_asset_type",
        ),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True)
    asset_type: Mapped[str] = mapped_column(String)
    manifest_hash: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class InferenceRecordRow(Base):
    __tablename__ = "inference_records"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid4()))
    input_hash: Mapped[str] = mapped_column(String)
    model_digest: Mapped[str] = mapped_column(String)
    config_hash: Mapped[str] = mapped_column(String)
    output_hash: Mapped[str] = mapped_column(String)
    sequence_number: Mapped[int] = mapped_column(Integer, unique=True)
    nonce: Mapped[str] = mapped_column(String, unique=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    previous_record_hash: Mapped[str] = mapped_column(String)
    merkle_root: Mapped[str | None] = mapped_column(String, nullable=True)
    record_hash: Mapped[str] = mapped_column(String)
    signature: Mapped[str] = mapped_column(String)


class FindingRow(Base):
    __tablename__ = "findings"
    __table_args__ = (
        CheckConstraint("severity >= 0 AND severity <= 1", name="ck_findings_severity"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_findings_confidence"),
        CheckConstraint(
            "modality IN ('PIXEL', 'EMBEDDING', 'ANNOTATION', 'ACTIVATION', 'BEHAVIORAL')",
            name="ck_findings_modality",
        ),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid4()))
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"))
    finding_type: Mapped[str] = mapped_column(String)
    severity: Mapped[float] = mapped_column(Float)
    confidence: Mapped[float] = mapped_column(Float)
    evidence: Mapped[list[str]] = mapped_column(JSON)
    modality: Mapped[str] = mapped_column(String)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSON)
    recommended_action: Mapped[str] = mapped_column(String)
    quarantine_scope: Mapped[str | None] = mapped_column(String, nullable=True)
    access_assumptions: Mapped[str] = mapped_column(String, default="black_box")
    counter_evidence: Mapped[list[str]] = mapped_column(JSON, default=list)


class AssessmentRow(Base):
    __tablename__ = "assessments"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid4()))
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    tier_logs: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    timings: Mapped[dict[str, Any]] = mapped_column(JSON)
    skipped: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    finding_count: Mapped[int] = mapped_column(Integer)
