"""SQLAlchemy engine, session factory, and ORM models."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Column, DateTime, Float, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings


class Base(DeclarativeBase):
    pass


class ScanRecord(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True)
    started_at = Column(DateTime, nullable=False)
    completed_at = Column(DateTime, nullable=False)
    duration_seconds = Column(Float, nullable=False)
    mode = Column(String(16), nullable=False)             # live | demo
    status = Column(String(16), nullable=False, default="completed")
    risk_score = Column(Integer, nullable=False)
    risk_grade = Column(String(2), nullable=False)
    total_findings = Column(Integer, nullable=False, default=0)
    severity_counts = Column(JSON, nullable=False, default=dict)
    service_scores = Column(JSON, nullable=False, default=dict)
    scanner_errors = Column(JSON, nullable=False, default=dict)


class FindingRecord(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True)
    scan_id = Column(String(36), nullable=False, index=True)
    fingerprint = Column(String(32), nullable=False, index=True)
    check_id = Column(String(64), nullable=False, index=True)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(16), nullable=False, index=True)
    severity_weight = Column(Integer, nullable=False)
    resource_type = Column(String(32), nullable=False, index=True)
    resource_id = Column(String(512), nullable=False)
    resource_name = Column(String(256), nullable=False)
    region = Column(String(32), nullable=False)
    remediation = Column(Text, nullable=False)
    evidence = Column(JSON, nullable=False, default=dict)
    compliance = Column(JSON, nullable=False, default=list)
    references = Column(JSON, nullable=False, default=list)
    status = Column(String(16), nullable=False, default="open", index=True)
    discovered_at = Column(DateTime, nullable=False)
    first_seen_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    last_seen_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False} if settings.database_url.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


def get_db():
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()
