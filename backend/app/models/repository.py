"""Persistence helpers translating between domain objects and ORM rows."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.core.orchestrator import ScanReport
from app.models.database import FindingRecord, ScanRecord


def save_scan_report(db: Session, report: ScanReport) -> None:
    scan_row = ScanRecord(
        id=report.scan_id,
        started_at=report.started_at,
        completed_at=report.completed_at,
        duration_seconds=report.duration_seconds,
        mode=report.mode,
        status="completed",
        risk_score=report.risk.score if report.risk else 0,
        risk_grade=report.risk.grade if report.risk else "F",
        total_findings=report.risk.total_findings if report.risk else len(report.findings),
        severity_counts=report.risk.severity_counts if report.risk else {},
        service_scores=report.risk.service_scores if report.risk else {},
        provider_scores=report.risk.provider_scores if report.risk else {},
        scanner_errors=report.scanner_errors,
    )
    db.add(scan_row)

    for f in report.findings:
        existing = (
            db.query(FindingRecord)
            .filter(FindingRecord.fingerprint == f.fingerprint, FindingRecord.status == "open")
            .order_by(desc(FindingRecord.last_seen_at))
            .first()
        )
        if existing:
            # Finding persists across scans - just bump last_seen and scan_id.
            existing.last_seen_at = datetime.now(timezone.utc)
            existing.scan_id = report.scan_id
            continue

        row = FindingRecord(
            id=f.id,
            scan_id=report.scan_id,
            fingerprint=f.fingerprint,
            check_id=f.check_id,
            title=f.title,
            description=f.description,
            severity=f.severity.value,
            severity_weight=f.severity.weight,
            provider=f.provider.value,
            resource_type=f.resource_type.value,
            resource_id=f.resource_id,
            resource_name=f.resource_name,
            region=f.region,
            remediation=f.remediation,
            evidence=f.evidence,
            compliance=[
                {"framework": c.framework, "control_id": c.control_id, "control_title": c.control_title}
                for c in f.compliance
            ],
            references=f.references,
            status=f.status.value,
            discovered_at=f.discovered_at,
        )
        db.add(row)

    db.commit()


def list_scans(db: Session, limit: int = 50) -> list[ScanRecord]:
    return db.query(ScanRecord).order_by(desc(ScanRecord.completed_at)).limit(limit).all()


def get_scan(db: Session, scan_id: str) -> ScanRecord | None:
    return db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()


def get_latest_scan(db: Session) -> ScanRecord | None:
    return db.query(ScanRecord).order_by(desc(ScanRecord.completed_at)).first()


def list_findings_for_scan(db: Session, scan_id: str) -> list[FindingRecord]:
    return db.query(FindingRecord).filter(FindingRecord.scan_id == scan_id).all()


def list_open_findings(
    db: Session, severity: str | None = None, resource_type: str | None = None,
    search: str | None = None, limit: int = 500, provider: str | None = None,
) -> list[FindingRecord]:
    query = db.query(FindingRecord).filter(FindingRecord.status == "open")
    if severity:
        query = query.filter(FindingRecord.severity == severity)
    if resource_type:
        query = query.filter(FindingRecord.resource_type == resource_type)
    if provider:
        query = query.filter(FindingRecord.provider == provider)
    if search:
        like = f"%{search}%"
        query = query.filter(
            (FindingRecord.title.ilike(like)) | (FindingRecord.resource_name.ilike(like))
        )
    return query.order_by(desc(FindingRecord.severity_weight)).limit(limit).all()


def update_finding_status(db: Session, finding_id: str, status: str) -> FindingRecord | None:
    row = db.query(FindingRecord).filter(FindingRecord.id == finding_id).first()
    if row:
        row.status = status
        db.commit()
        db.refresh(row)
    return row
