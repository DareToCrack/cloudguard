"""Scan orchestrator - runs the full scanner suite and aggregates results."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.core.finding import Finding
from app.core.risk_engine import RiskScoreResult, calculate_risk_score
from app.scanners.azure_authorization_scanner import AzureAuthorizationScanner
from app.scanners.azure_disk_scanner import AzureDiskScanner
from app.scanners.azure_keyvault_scanner import AzureKeyVaultScanner
from app.scanners.azure_network_scanner import AzureNetworkScanner
from app.scanners.azure_sql_scanner import AzureSqlScanner
from app.scanners.azure_storage_scanner import AzureStorageScanner
from app.scanners.base import AWSSessionManager, AzureSessionManager
from app.scanners.logging_scanner import CloudTrailScanner, EBSScanner
from app.scanners.iam_scanner import IAMScanner
from app.scanners.rds_scanner import RDSScanner
from app.scanners.s3_scanner import S3Scanner
from app.scanners.security_group_scanner import SecurityGroupScanner

logger = logging.getLogger("cloudguard.orchestrator")

AWS_SCANNER_REGISTRY = [
    S3Scanner,
    IAMScanner,
    SecurityGroupScanner,
    RDSScanner,
    CloudTrailScanner,
    EBSScanner,
]

AZURE_SCANNER_REGISTRY = [
    AzureStorageScanner,
    AzureNetworkScanner,
    AzureAuthorizationScanner,
    AzureSqlScanner,
    AzureKeyVaultScanner,
    AzureDiskScanner,
]

SCANNER_REGISTRY = AWS_SCANNER_REGISTRY + AZURE_SCANNER_REGISTRY

#: valid values for the `provider` scan parameter
PROVIDERS = ("all", "aws", "azure")


@dataclass
class ScanReport:
    scan_id: str
    started_at: datetime
    completed_at: datetime
    duration_seconds: float
    mode: str                      # "live", "demo", or "mixed"
    findings: list[Finding] = field(default_factory=list)
    risk: RiskScoreResult | None = None
    scanner_errors: dict[str, str] = field(default_factory=dict)
    providers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "duration_seconds": round(self.duration_seconds, 3),
            "mode": self.mode,
            "providers": self.providers,
            "findings": [f.to_dict() for f in self.findings],
            "risk": self.risk.to_dict() if self.risk else None,
            "scanner_errors": self.scanner_errors,
        }


class ScanOrchestrator:
    """Coordinates running every registered scanner and aggregating output.

    `provider` selects which cloud(s) to scan: "all" (default), "aws", or
    "azure". Each provider resolves its own live/demo mode independently:
    the overall scan mode is "live" when every selected provider is live,
    "demo" when none is, and "mixed" when some are live and some fell
    back to demo data.
    """

    def __init__(
        self,
        profile: str | None = None,
        region: str = "us-east-1",
        provider: str = "all",
        azure_subscription_id: str | None = None,
    ) -> None:
        if provider not in PROVIDERS:
            raise ValueError(f"provider must be one of {PROVIDERS}, got {provider!r}")
        self.provider = provider
        self.session_manager = AWSSessionManager(profile=profile, region=region)
        self.azure_session_manager = AzureSessionManager(
            subscription_id=azure_subscription_id
        )

    def _scanners_for_provider(self) -> list:
        if self.provider == "aws":
            return list(AWS_SCANNER_REGISTRY)
        if self.provider == "azure":
            return list(AZURE_SCANNER_REGISTRY)
        return list(SCANNER_REGISTRY)

    def _session_manager_for(self, scanner_cls):
        if getattr(scanner_cls, "provider", "aws") == "azure":
            return self.azure_session_manager
        return self.session_manager

    def _providers_scanned(self) -> list[str]:
        if self.provider == "all":
            return ["aws", "azure"]
        return [self.provider]

    def _scan_mode(self) -> str:
        live = []
        if self.provider in ("all", "aws"):
            live.append(self.session_manager.is_live)
        if self.provider in ("all", "azure"):
            live.append(self.azure_session_manager.is_live)
        if all(live):
            return "live"
        if not any(live):
            return "demo"
        return "mixed"

    def run_full_scan(self, scan_id: str) -> ScanReport:
        started_at = datetime.now(timezone.utc)
        t0 = time.monotonic()
        logger.info(
            "Starting scan %s (provider=%s, region=%s)",
            scan_id, self.provider, self.session_manager.region,
        )

        all_findings: list[Finding] = []
        errors: dict[str, str] = {}

        for scanner_cls in self._scanners_for_provider():
            scanner = scanner_cls(self._session_manager_for(scanner_cls))
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
        mode = self._scan_mode()

        logger.info(
            "Scan %s complete: %d findings, score=%d (%s), mode=%s, duration=%.2fs",
            scan_id, len(all_findings), risk.score, risk.grade, mode, duration,
        )

        return ScanReport(
            scan_id=scan_id,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            mode=mode,
            findings=all_findings,
            risk=risk,
            scanner_errors=errors,
            providers=self._providers_scanned(),
        )
