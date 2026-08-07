"""Scan orchestrator - runs the full scanner suite and aggregates results."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.core.finding import Finding
from app.core.risk_engine import RiskScoreResult, calculate_risk_score
from app.scanners.base import AWSSessionManager
from app.scanners.logging_scanner import CloudTrailScanner, EBSScanner
from app.scanners.iam_scanner import IAMScanner
from app.scanners.rds_scanner import RDSScanner
from app.scanners.s3_scanner import S3Scanner
from app.scanners.security_group_scanner import SecurityGroupScanner

logger = logging.getLogger("cloudguard.orchestrator")

SCANNER_REGISTRY = [
    S3Scanner,
    IAMScanner,
    SecurityGroupScanner,
    RDSScanner,
    CloudTrailScanner,
    EBSScanner,
]


@dataclass
class ScanReport:
    scan_id: str
    started_at: datetime
    completed_at: datetime
    duration_seconds: float
    mode: str                      # "live" or "demo"
    findings: list[Finding] = field(default_factory=list)
    risk: RiskScoreResult | None = None
    scanner_errors: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "duration_seconds": round(self.duration_seconds, 3),
            "mode": self.mode,
            "findings": [f.to_dict() for f in self.findings],
            "risk": self.risk.to_dict() if self.risk else None,
            "scanner_errors": self.scanner_errors,
        }


class ScanOrchestrator:
    """Coordinates running every registered scanner and aggregating output."""

    def __init__(self, profile: str | None = None, region: str = "us-east-1") -> None:
        self.session_manager = AWSSessionManager(profile=profile, region=region)

    def run_full_scan(self, scan_id: str) -> ScanReport:
        started_at = datetime.now(timezone.utc)
        t0 = time.monotonic()
        logger.info("Starting scan %s (region=%s)", scan_id, self.session_manager.region)

        all_findings: list[Finding] = []
        errors: dict[str, str] = {}

        for scanner_cls in SCANNER_REGISTRY:
            scanner = scanner_cls(self.session_manager)
            try:
                findings = scanner.run()
                all_findings.extend(findings)
                logger.info("%s: %d finding(s)", scanner.name, len(findings))
            except Exception as exc:  # noqa: BLE001
                logger.exception("%s failed", scanner.name)
                errors[scanner.name] = str(exc)

        risk = calculate_risk_score(all_findings)
        completed_at = datetime.now(timezone.utc)
        duration = time.monotonic() - t0

        logger.info(
            "Scan %s complete: %d findings, score=%d (%s), duration=%.2fs",
            scan_id, len(all_findings), risk.score, risk.grade, duration,
        )

        return ScanReport(
            scan_id=scan_id,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            mode="live" if self.session_manager.is_live else "demo",
            findings=all_findings,
            risk=risk,
            scanner_errors=errors,
        )
