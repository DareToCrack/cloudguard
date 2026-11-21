"""Report generation and export endpoints."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session

from app.core.enums import CloudProvider, FindingStatus, ResourceType, Severity
from app.core.finding import ComplianceMapping, Finding
from app.core.orchestrator import ScanReport
from app.core.risk_engine import calculate_risk_score
from app.models import repository
from app.models.database import get_db
from app.reporting.html_report import generate_html_report

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _scan_report_from_db(db: Session, scan_id: str) -> ScanReport:
    scan_row = repository.get_scan(db, scan_id)
    if not scan_row:
        raise HTTPException(404, "Scan not found.")
    finding_rows = repository.list_findings_for_scan(db, scan_id)

    findings: list[Finding] = []
    for r in finding_rows:
        f = Finding(
            check_id=r.check_id,
            title=r.title,
            description=r.description,
            severity=Severity(r.severity),
            provider=CloudProvider(getattr(r, "provider", None) or "aws"),
            resource_type=ResourceType(r.resource_type),
            resource_id=r.resource_id,
            resource_name=r.resource_name,
            region=r.region,
            remediation=r.remediation,
            evidence=r.evidence or {},
            compliance=[
                ComplianceMapping(c["framework"], c["control_id"], c["control_title"])
                for c in (r.compliance or [])
            ],
            references=r.references or [],
            status=FindingStatus(r.status),
        )
        # preserve original id/fingerprint/discovered_at
        f.id = r.id
        f.fingerprint = r.fingerprint
        f.discovered_at = r.discovered_at
        findings.append(f)

    risk = calculate_risk_score(findings)
    return ScanReport(
        scan_id=scan_row.id,
        started_at=scan_row.started_at,
        completed_at=scan_row.completed_at,
        duration_seconds=scan_row.duration_seconds,
        mode=scan_row.mode,
        findings=findings,
        risk=risk,
        scanner_errors=scan_row.scanner_errors or {},
    )


@router.get("/{scan_id}/html", response_class=HTMLResponse)
def get_html_report(scan_id: str, db: Session = Depends(get_db)):
    report = _scan_report_from_db(db, scan_id)
    return HTMLResponse(content=generate_html_report(report))


@router.get("/{scan_id}/json")
def get_json_report(scan_id: str, db: Session = Depends(get_db)):
    report = _scan_report_from_db(db, scan_id)
    return JSONResponse(content=report.to_dict())
