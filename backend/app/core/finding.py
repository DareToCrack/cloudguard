"""Canonical Finding object produced by every scanner check."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.core.enums import FindingStatus, ResourceType, Severity


@dataclass
class ComplianceMapping:
    """Maps a finding to one or more compliance framework controls."""

    framework: str          # e.g. "CIS AWS Foundations Benchmark v3.0"
    control_id: str         # e.g. "1.4"
    control_title: str      # e.g. "Ensure no root user access key exists"


@dataclass
class Finding:
    """A single, normalized misconfiguration or risk finding.

    Every scanner check returns zero or more `Finding` instances. This is the
    canonical unit persisted to the database, scored by the risk engine, and
    rendered into reports.
    """

    check_id: str                       # stable id, e.g. "S3_PUBLIC_READ"
    title: str
    description: str
    severity: Severity
    resource_type: ResourceType
    resource_id: str                    # ARN or provider-native identifier
    resource_name: str
    region: str
    remediation: str
    evidence: dict[str, Any] = field(default_factory=dict)
    compliance: list[ComplianceMapping] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    status: FindingStatus = FindingStatus.OPEN
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        # Stable fingerprint so re-scans can de-duplicate / track finding age
        # instead of creating a new row every run.
        raw = f"{self.check_id}:{self.resource_id}:{self.region}"
        self.fingerprint = hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "fingerprint": self.fingerprint,
            "check_id": self.check_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "severity_weight": self.severity.weight,
            "resource_type": self.resource_type.value,
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "region": self.region,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "compliance": [
                {
                    "framework": c.framework,
                    "control_id": c.control_id,
                    "control_title": c.control_title,
                }
                for c in self.compliance
            ],
            "references": self.references,
            "status": self.status.value,
            "discovered_at": self.discovered_at.isoformat(),
        }
