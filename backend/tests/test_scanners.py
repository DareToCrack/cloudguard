"""Unit tests for each scanner module against the bundled demo dataset."""

from __future__ import annotations

from app.core.enums import Severity
from app.scanners.iam_scanner import IAMScanner
from app.scanners.logging_scanner import CloudTrailScanner, EBSScanner
from app.scanners.rds_scanner import RDSScanner
from app.scanners.s3_scanner import S3Scanner
from app.scanners.security_group_scanner import SecurityGroupScanner


def test_s3_scanner_flags_public_write_as_critical(demo_session):
    findings = S3Scanner(demo_session).run()
    public_write = [f for f in findings if f.check_id == "S3_PUBLIC_WRITE"]
    assert public_write, "expected at least one public-write bucket finding in demo data"
    assert public_write[0].severity == Severity.CRITICAL


def test_s3_scanner_does_not_flag_intended_public_bucket_as_read_finding(demo_session):
    findings = S3Scanner(demo_session).run()
    names_flagged_read = {f.resource_name for f in findings if f.check_id == "S3_PUBLIC_READ"}
    assert "static-website-assets" not in names_flagged_read


def test_s3_scanner_flags_missing_encryption(demo_session):
    findings = S3Scanner(demo_session).run()
    no_enc = [f for f in findings if f.check_id == "S3_NO_ENCRYPTION"]
    assert any(f.resource_name == "prod-app-logs-2024" for f in no_enc)


def test_iam_scanner_flags_root_mfa_disabled(demo_session):
    findings = IAMScanner(demo_session).run()
    assert any(f.check_id == "IAM_ROOT_MFA_DISABLED" for f in findings)


def test_iam_scanner_flags_console_user_without_mfa(demo_session):
    findings = IAMScanner(demo_session).run()
    no_mfa = [f for f in findings if f.check_id == "IAM_NO_MFA_CONSOLE"]
    names = {f.resource_name for f in no_mfa}
    assert "root-break-glass" in names
    # jsmith has MFA enabled in demo data - must NOT be flagged
    assert "jsmith" not in names


def test_iam_scanner_flags_admin_policy_on_user(demo_session):
    findings = IAMScanner(demo_session).run()
    admin_flags = [f for f in findings if f.check_id == "IAM_ADMIN_POLICY_ATTACHED"]
    assert any(f.resource_name == "svc-ci-deploy" for f in admin_flags)


def test_iam_scanner_flags_old_access_keys(demo_session):
    findings = IAMScanner(demo_session).run()
    rotation_flags = [f for f in findings if f.check_id == "IAM_ACCESS_KEY_ROTATION"]
    assert any(f.resource_name == "svc-ci-deploy" for f in rotation_flags)


def test_security_group_scanner_flags_ssh_open_to_world(demo_session):
    findings = SecurityGroupScanner(demo_session).run()
    ssh_findings = [f for f in findings if f.check_id == "SG_SSH_OPEN_WORLD"]
    assert any(f.resource_name == "web-prod-sg" for f in ssh_findings)
    assert ssh_findings[0].severity == Severity.CRITICAL


def test_security_group_scanner_flags_rdp_open_to_world(demo_session):
    findings = SecurityGroupScanner(demo_session).run()
    assert any(f.check_id == "SG_RDP_OPEN_WORLD" for f in findings)


def test_security_group_scanner_flags_all_traffic_rule(demo_session):
    findings = SecurityGroupScanner(demo_session).run()
    all_traffic = [f for f in findings if f.check_id == "SG_ALL_TRAFFIC_OPEN"]
    assert any(f.resource_name == "all-traffic-legacy" for f in all_traffic)


def test_security_group_scanner_flags_database_port_open(demo_session):
    findings = SecurityGroupScanner(demo_session).run()
    db_open = [f for f in findings if f.check_id == "SG_DATABASE_PORT_OPEN_WORLD"]
    assert any(f.resource_name == "db-prod-sg" for f in db_open)


def test_security_group_scanner_does_not_flag_internal_only_group(demo_session):
    findings = SecurityGroupScanner(demo_session).run()
    flagged_names = {f.resource_name for f in findings}
    assert "internal-services-sg" not in flagged_names


def test_rds_scanner_flags_public_instance(demo_session):
    findings = RDSScanner(demo_session).run()
    assert any(f.check_id == "RDS_PUBLIC_ACCESS" and f.resource_name == "db-prod-main" for f in findings)


def test_rds_scanner_does_not_flag_well_configured_instance(demo_session):
    findings = RDSScanner(demo_session).run()
    warehouse_findings = [f for f in findings if f.resource_name == "db-analytics-warehouse"]
    assert warehouse_findings == []


def test_cloudtrail_scanner_runs_against_demo_data(demo_session):
    findings = CloudTrailScanner(demo_session).run()
    # Demo trail is single-region, so at minimum that check should fire.
    assert any(f.check_id == "CLOUDTRAIL_NOT_MULTI_REGION" for f in findings)


def test_ebs_scanner_flags_unencrypted_volumes(demo_session):
    findings = EBSScanner(demo_session).run()
    unencrypted = [f for f in findings if f.check_id == "EBS_NOT_ENCRYPTED"]
    assert len(unencrypted) == 2  # two unencrypted volumes in demo data


def test_all_findings_have_remediation_and_compliance_or_reference(demo_session):
    """Every finding must be actionable: it needs remediation guidance, and
    should generally map to at least one compliance control or reference."""
    all_findings = (
        S3Scanner(demo_session).run()
        + IAMScanner(demo_session).run()
        + SecurityGroupScanner(demo_session).run()
        + RDSScanner(demo_session).run()
    )
    for f in all_findings:
        assert f.remediation, f"{f.check_id} is missing remediation text"
        assert f.compliance or f.references, f"{f.check_id} has no compliance mapping or references"
