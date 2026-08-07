"""Scan lifecycle endpoints: trigger, list, retrieve."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.schemas import (
    FindingOut, ScanSummaryOut, ScanTriggerRequest, ScanTriggerResponse,
)
from app.core.orchestrator import ScanOrchestrator
from app.models import repository
from app.models.database import get_db

router = APIRouter(prefix="/api/scans", tags=["scans"])

# In-memory tracker for in-flight background scans (sufficient for a
# single-process demo deployment; a production system would use a task
# queue such as Celery/RQ backed by Redis - see docs/ARCHITECTURE.md).
_SCAN_STATE: dict[str, str] = {}


def _run_scan_background(scan_id: str, region: str, profile: str | None) -> None:
    from app.models.database import SessionLocal

    _SCAN_STATE[scan_id] = "running"
    db = SessionLocal()
    try:
        orchestrator = ScanOrchestrator(profile=profile, region=region)
        report = orchestrator.run_full_scan(scan_id)
        repository.save_scan_report(db, report)
        _SCAN_STATE[scan_id] = "completed"
    except Exception:  # noqa: BLE001
        _SCAN_STATE[scan_id] = "failed"
        raise
    finally:
        db.close()


@router.post("", response_model=ScanTriggerResponse, status_code=202)
def trigger_scan(payload: ScanTriggerRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    _SCAN_STATE[scan_id] = "pending"
    background_tasks.add_task(_run_scan_background, scan_id, payload.region, payload.aws_profile)
    return ScanTriggerResponse(
        scan_id=scan_id, status="pending",
        message="Scan started. Poll GET /api/scans/{scan_id} for status.",
    )


@router.post("/sync", response_model=ScanSummaryOut, status_code=201)
def trigger_scan_sync(payload: ScanTriggerRequest, db: Session = Depends(get_db)):
    """Run a scan synchronously and return the result immediately.

    Useful for CLI usage and for the demo dataset, where a scan completes
    in well under a second.
    """
    scan_id = str(uuid.uuid4())
    orchestrator = ScanOrchestrator(profile=payload.aws_profile, region=payload.region)
    report = orchestrator.run_full_scan(scan_id)
    repository.save_scan_report(db, report)
    row = repository.get_scan(db, scan_id)
    if not row:
        raise HTTPException(500, "Scan completed but could not be retrieved.")
    return row


@router.get("", response_model=list[ScanSummaryOut])
def list_scans(limit: int = 50, db: Session = Depends(get_db)):
    return repository.list_scans(db, limit=limit)


@router.get("/{scan_id}", response_model=ScanSummaryOut)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    row = repository.get_scan(db, scan_id)
    if not row:
        state = _SCAN_STATE.get(scan_id)
        if state in ("pending", "running"):
            raise HTTPException(202, f"Scan is still {state}.")
        raise HTTPException(404, "Scan not found.")
    return row


@router.get("/{scan_id}/findings", response_model=list[FindingOut])
def get_scan_findings(scan_id: str, db: Session = Depends(get_db)):
    rows = repository.list_findings_for_scan(db, scan_id)
    if not rows:
        if not repository.get_scan(db, scan_id):
            raise HTTPException(404, "Scan not found.")
    return rows
