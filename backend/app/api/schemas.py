"""Pydantic request/response schemas for the REST API."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class ComplianceMappingOut(BaseModel):
    framework: str
    control_id: str
    control_title: str


class FindingOut(BaseModel):
    id: str
    fingerprint: str
    check_id: str
    title: str
    description: str
    severity: str
    severity_weight: int
    provider: str = "aws"
    resource_type: str
    resource_id: str
    resource_name: str
    region: str
    remediation: str
    evidence: dict
    compliance: list[dict]
    references: list[str]
    status: str
    discovered_at: datetime | str

    class Config:
        from_attributes = True


class RiskSummaryOut(BaseModel):
    score: int
    grade: str
    severity_counts: dict[str, int]
    service_scores: dict[str, int]
    provider_scores: dict[str, int] = {}
    total_findings: int


class ScanSummaryOut(BaseModel):
    id: str
    started_at: datetime
    completed_at: datetime
    duration_seconds: float
    mode: str
    status: str
    risk_score: int
    risk_grade: str
    total_findings: int
    severity_counts: dict
    service_scores: dict
    provider_scores: dict = {}
    scanner_errors: dict

    class Config:
        from_attributes = True


class ScanTriggerRequest(BaseModel):
    region: str = Field(default="us-east-1")
    aws_profile: str | None = None
    provider: str = Field(default="all", pattern="^(all|aws|azure)$")
    azure_subscription_id: str | None = None


class ScanTriggerResponse(BaseModel):
    scan_id: str
    status: str
    message: str


class FindingStatusUpdate(BaseModel):
    status: str  # open | resolved | suppressed | risk_accepted


class DashboardOut(BaseModel):
    latest_scan: ScanSummaryOut | None
    total_scans: int
    trend: list[dict]  # [{scan_id, completed_at, score}, ...]
