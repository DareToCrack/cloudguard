"""Findings management, dashboard summary, and compliance overview endpoints."""

from __future__ import annotations

from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.schemas import DashboardOut, FindingOut, FindingStatusUpdate, ScanSummaryOut
from app.models import repository
from app.models.database import FindingRecord, ScanRecord, get_db

router = APIRouter(prefix="/api", tags=["findings"])


@router.get("/findings", response_model=list[FindingOut])
def list_findings(
    severity: str | None = None,
    resource_type: str | None = None,
    search: str | None = None,
    limit: int = 500,
    db: Session = Depends(get_db),
):
    return repository.list_open_findings(
        db, severity=severity, resource_type=resource_type, search=search, limit=limit
    )


@router.patch("/findings/{finding_id}", response_model=FindingOut)
def update_finding(finding_id: str, payload: FindingStatusUpdate, db: Session = Depends(get_db)):
    valid_statuses = {"open", "resolved", "suppressed", "risk_accepted"}
    if payload.status not in valid_statuses:
        raise HTTPException(400, f"status must be one of {sorted(valid_statuses)}")
    row = repository.update_finding_status(db, finding_id, payload.status)
    if not row:
        raise HTTPException(404, "Finding not found.")
    return row


@router.get("/dashboard", response_model=DashboardOut)
def dashboard(db: Session = Depends(get_db)):
    latest = repository.get_latest_scan(db)
    all_scans = repository.list_scans(db, limit=20)
    trend = [
        {"scan_id": s.id, "completed_at": s.completed_at.isoformat(), "score": s.risk_score}
        for s in reversed(all_scans)
    ]
    return DashboardOut(
        latest_scan=latest,
        total_scans=db.query(ScanRecord).count(),
        trend=trend,
    )


@router.get("/compliance/summary")
def compliance_summary(db: Session = Depends(get_db)):
    """Aggregate open findings by compliance framework control for a
    posture-vs-framework view (e.g. 'CIS AWS 2.1.1: 3 open findings')."""
    findings = repository.list_open_findings(db, limit=5000)
    by_control: dict[str, dict] = {}
    for f in findings:
        for c in f.compliance or []:
            key = f"{c['framework']} - {c['control_id']}"
            entry = by_control.setdefault(key, {
                "framework": c["framework"],
                "control_id": c["control_id"],
                "control_title": c["control_title"],
                "open_findings": 0,
                "highest_severity": "info",
            })
            entry["open_findings"] += 1

    severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    by_control_severity: dict[str, str] = defaultdict(lambda: "info")
    for f in findings:
        for c in f.compliance or []:
            key = f"{c['framework']} - {c['control_id']}"
            if severity_rank[f.severity] > severity_rank[by_control_severity[key]]:
                by_control_severity[key] = f.severity

    for key, entry in by_control.items():
        entry["highest_severity"] = by_control_severity[key]

    return {"controls": sorted(by_control.values(), key=lambda c: -severity_rank[c["highest_severity"]])}
