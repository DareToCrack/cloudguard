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
    mode = Column(String(16), nullable=False)             # live | demo | mixed
    status = Column(String(16), nullable=False, default="completed")
    risk_score = Column(Integer, nullable=False)
    risk_grade = Column(String(2), nullable=False)
    total_findings = Column(Integer, nullable=False, default=0)
    severity_counts = Column(JSON, nullable=False, default=dict)
    service_scores = Column(JSON, nullable=False, default=dict)
    provider_scores = Column(JSON, nullable=False, default=dict)
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
    provider = Column(String(16), nullable=False, default="aws", index=True)
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
    _migrate_add_provider_columns()


def _migrate_add_provider_columns() -> None:
    """Lightweight migration for databases created before the provider
    columns existed (pre-Azure versions of CloudGuard).

    `create_all` only creates missing *tables*, not missing *columns*, so
    an existing database would otherwise fail on any query touching the
    new columns. Adding a column with a default is a safe, idempotent
    SQLite/PostgreSQL operation; anything unexpected is ignored so a
    fresh database (where the columns already exist) is unaffected.
    """
    from sqlalchemy import inspect, text

    try:
        inspector = inspect(engine)
        findings_cols = {c["name"] for c in inspector.get_columns("findings")}
        scans_cols = {c["name"] for c in inspector.get_columns("scans")}
        with engine.begin() as conn:
            if "provider" not in findings_cols:
                conn.execute(
                    text("ALTER TABLE findings ADD COLUMN provider VARCHAR(16) NOT NULL DEFAULT 'aws'")
                )
            if "provider_scores" not in scans_cols:
                conn.execute(
                    text("ALTER TABLE scans ADD COLUMN provider_scores JSON NOT NULL DEFAULT '{}'")
                )
    except Exception:  # noqa: BLE001 - migration is best-effort
        pass


def get_db():
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()
