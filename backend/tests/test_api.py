"""Integration tests for the FastAPI application using an isolated SQLite DB."""

from __future__ import annotations

import os
import tempfile

import pytest

# Point at a throwaway SQLite file before importing the app so the engine
# picks it up at import time.
_tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
os.environ["CLOUDGUARD_DATABASE_URL"] = f"sqlite:///{_tmp_db.name}"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

# Using the context-manager form triggers FastAPI's startup event (which
# calls init_db() to create tables) before any requests are made.
client = TestClient(app)
with client:
    pass


def test_health_check():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_trigger_sync_scan_and_fetch_it():
    resp = client.post("/api/scans/sync", json={"region": "us-east-1"})
    assert resp.status_code == 201
    body = resp.json()
    assert body["mode"] == "demo"
    assert body["total_findings"] > 0

    scan_id = body["id"]
    resp2 = client.get(f"/api/scans/{scan_id}")
    assert resp2.status_code == 200
    assert resp2.json()["id"] == scan_id


def test_list_scans_returns_at_least_one():
    client.post("/api/scans/sync", json={"region": "us-east-1"})
    resp = client.get("/api/scans")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1


def test_get_findings_for_scan():
    scan = client.post("/api/scans/sync", json={"region": "us-east-1"}).json()
    resp = client.get(f"/api/scans/{scan['id']}/findings")
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) > 0
    assert "severity" in findings[0]


def test_get_nonexistent_scan_returns_404():
    resp = client.get("/api/scans/does-not-exist")
    assert resp.status_code == 404


def test_dashboard_endpoint():
    client.post("/api/scans/sync", json={"region": "us-east-1"})
    resp = client.get("/api/dashboard")
    assert resp.status_code == 200
    body = resp.json()
    assert body["latest_scan"] is not None
    assert body["total_scans"] >= 1


def test_update_finding_status():
    scan = client.post("/api/scans/sync", json={"region": "us-east-1"}).json()
    findings = client.get(f"/api/scans/{scan['id']}/findings").json()
    finding_id = findings[0]["id"]

    resp = client.patch(f"/api/findings/{finding_id}", json={"status": "resolved"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "resolved"


def test_update_finding_with_invalid_status_rejected():
    scan = client.post("/api/scans/sync", json={"region": "us-east-1"}).json()
    findings = client.get(f"/api/scans/{scan['id']}/findings").json()
    finding_id = findings[0]["id"]

    resp = client.patch(f"/api/findings/{finding_id}", json={"status": "not-a-real-status"})
    assert resp.status_code == 400


def test_html_report_generation():
    scan = client.post("/api/scans/sync", json={"region": "us-east-1"}).json()
    resp = client.get(f"/api/reports/{scan['id']}/html")
    assert resp.status_code == 200
    assert "CloudGuard" in resp.text
    assert "text/html" in resp.headers["content-type"]


def test_compliance_summary_endpoint():
    client.post("/api/scans/sync", json={"region": "us-east-1"})
    resp = client.get("/api/compliance/summary")
    assert resp.status_code == 200
    assert "controls" in resp.json()


def test_sync_scan_with_azure_provider_only():
    resp = client.post("/api/scans/sync", json={"region": "us-east-1", "provider": "azure"})
    assert resp.status_code == 201
    body = resp.json()
    assert body["total_findings"] > 0
    assert set(body["provider_scores"]) == {"azure"}

    findings = client.get(f"/api/scans/{body['id']}/findings").json()
    assert findings
    assert all(f["provider"] == "azure" for f in findings)


def test_sync_scan_with_invalid_provider_rejected():
    resp = client.post("/api/scans/sync", json={"region": "us-east-1", "provider": "gcp"})
    assert resp.status_code == 422


def test_findings_endpoint_filters_by_provider():
    client.post("/api/scans/sync", json={"region": "us-east-1", "provider": "all"})
    resp = client.get("/api/findings?provider=azure&limit=1000")
    assert resp.status_code == 200
    findings = resp.json()
    assert findings
    assert all(f["provider"] == "azure" for f in findings)
    assert any(f["check_id"].startswith("AZ_") for f in findings)


@pytest.fixture(scope="session", autouse=True)
def cleanup():
    yield
    try:
        os.unlink(_tmp_db.name)
    except OSError:
        pass
