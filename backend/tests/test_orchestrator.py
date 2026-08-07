"""Tests for the scan orchestrator's end-to-end behavior in demo mode."""

from __future__ import annotations

from app.core.orchestrator import ScanOrchestrator


def test_full_demo_scan_produces_findings_and_risk_score():
    orchestrator = ScanOrchestrator(region="us-east-1")
    report = orchestrator.run_full_scan("test-scan-1")

    assert report.mode == "demo"
    assert len(report.findings) > 0
    assert report.risk is not None
    assert 0 <= report.risk.score <= 100
    assert report.scanner_errors == {}


def test_scan_report_serializes_to_dict():
    orchestrator = ScanOrchestrator(region="us-east-1")
    report = orchestrator.run_full_scan("test-scan-2")
    data = report.to_dict()

    assert data["scan_id"] == "test-scan-2"
    assert data["mode"] == "demo"
    assert isinstance(data["findings"], list)
    assert "risk" in data


def test_repeated_scans_are_idempotent_in_finding_content():
    orchestrator = ScanOrchestrator(region="us-east-1")
    report1 = orchestrator.run_full_scan("scan-a")
    report2 = orchestrator.run_full_scan("scan-b")

    # Same demo dataset -> same fingerprints across scans (finding identity
    # is stable even though scan IDs differ).
    fp1 = {f.fingerprint for f in report1.findings}
    fp2 = {f.fingerprint for f in report2.findings}
    assert fp1 == fp2
