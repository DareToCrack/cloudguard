"""Unit tests for the Azure scanner modules, provider model, and scoring.

All tests run against the bundled synthetic Azure inventory or mocked SDK
clients - no live Azure credentials are ever required.
"""

from __future__ import annotations

from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.enums import CloudProvider, ResourceType, Severity
from app.core.orchestrator import ScanOrchestrator
from app.core.risk_engine import calculate_risk_score
from app.models import repository
from app.models.database import Base
from app.scanners.azure_authorization_scanner import AzureAuthorizationScanner
from app.scanners.azure_disk_scanner import AzureDiskScanner
from app.scanners.azure_keyvault_scanner import AzureKeyVaultScanner
from app.scanners.azure_network_scanner import AzureNetworkScanner
from app.scanners.azure_sql_scanner import AzureSqlScanner
from app.scanners.azure_storage_scanner import AzureStorageScanner
from app.scanners.base import AzureSessionManager

AZURE_SCANNERS = [
    AzureStorageScanner,
    AzureNetworkScanner,
    AzureAuthorizationScanner,
    AzureSqlScanner,
    AzureKeyVaultScanner,
    AzureDiskScanner,
]


# -- storage ---------------------------------------------------------------

def test_storage_scanner_flags_public_blob_access(azure_demo_session):
    findings = AzureStorageScanner(azure_demo_session).run()
    public = [f for f in findings if f.check_id == "AZ_STORAGE_PUBLIC_BLOB"]
    assert any(f.resource_name == "prodstorageacct" for f in public)
    assert public[0].severity == Severity.HIGH


def test_storage_scanner_does_not_flag_intended_public_account(azure_demo_session):
    findings = AzureStorageScanner(azure_demo_session).run()
    names = {f.resource_name for f in findings if f.check_id == "AZ_STORAGE_PUBLIC_BLOB"}
    assert "webstaticassets" not in names


def test_storage_scanner_flags_https_tls_and_network(azure_demo_session):
    findings = AzureStorageScanner(azure_demo_session).run()
    by_check = {f.check_id for f in findings}
    assert "AZ_STORAGE_HTTPS_ONLY" in by_check
    assert "AZ_STORAGE_MIN_TLS" in by_check
    assert "AZ_STORAGE_NETWORK_OPEN" in by_check
    assert "AZ_STORAGE_NO_ENCRYPTION" in by_check


def test_storage_scanner_does_not_flag_clean_account(azure_demo_session):
    findings = AzureStorageScanner(azure_demo_session).run()
    flagged = {f.resource_name for f in findings}
    assert "financedocsprod" not in flagged


# -- network ---------------------------------------------------------------

def test_nsg_scanner_flags_ssh_open_to_world(azure_demo_session):
    findings = AzureNetworkScanner(azure_demo_session).run()
    ssh = [f for f in findings if f.check_id == "AZ_NSG_SSH_OPEN_WORLD"]
    assert any(f.resource_name == "nsg-web-prod" for f in ssh)
    assert ssh[0].severity == Severity.CRITICAL


def test_nsg_scanner_flags_rdp_open_to_world(azure_demo_session):
    findings = AzureNetworkScanner(azure_demo_session).run()
    assert any(f.check_id == "AZ_NSG_RDP_OPEN_WORLD" for f in findings)


def test_nsg_scanner_flags_wildcard_rule_once(azure_demo_session):
    findings = AzureNetworkScanner(azure_demo_session).run()
    any_port = [f for f in findings if f.check_id == "AZ_NSG_ANY_PORT_OPEN_WORLD"]
    assert len(any_port) == 1
    assert any_port[0].resource_name == "nsg-legacy-all"
    # The wildcard rule must not ALSO fire the SSH/RDP checks.
    assert not [f for f in findings
                if f.resource_name == "nsg-legacy-all"
                and f.check_id in ("AZ_NSG_SSH_OPEN_WORLD", "AZ_NSG_RDP_OPEN_WORLD")]


def test_nsg_scanner_does_not_flag_internal_only_group(azure_demo_session):
    findings = AzureNetworkScanner(azure_demo_session).run()
    assert "nsg-internal" not in {f.resource_name for f in findings}


# -- authorization -----------------------------------------------------------

def test_authorization_scanner_flags_broad_owner_and_contributor(azure_demo_session):
    findings = AzureAuthorizationScanner(azure_demo_session).run()
    owner = [f for f in findings if f.check_id == "AZ_RBAC_BROAD_OWNER"]
    assert len(owner) == 1
    assert owner[0].severity == Severity.HIGH
    assert "alice@contoso.com" in owner[0].resource_name
    contributor = [f for f in findings if f.check_id == "AZ_RBAC_BROAD_CONTRIBUTOR"]
    assert len(contributor) == 1
    assert contributor[0].severity == Severity.MEDIUM


def test_authorization_scanner_ignores_resource_group_scoped_roles(azure_demo_session):
    findings = AzureAuthorizationScanner(azure_demo_session).run()
    # The Contributor assignment scoped to rg-web-prod must not be flagged.
    assert not [f for f in findings if "spn-deploy-pipeline" in f.resource_name]


def test_authorization_scanner_flags_unused_custom_role(azure_demo_session):
    findings = AzureAuthorizationScanner(azure_demo_session).run()
    unused = [f for f in findings if f.check_id == "AZ_ROLE_UNUSED_CUSTOM"]
    assert len(unused) == 1
    assert unused[0].resource_name == "CustomDeployer"


# -- SQL ---------------------------------------------------------------------

def test_sql_scanner_flags_public_auditing_and_tde(azure_demo_session):
    findings = AzureSqlScanner(azure_demo_session).run()
    by_check = {f.check_id for f in findings if f.resource_name == "sql-prod-main"}
    assert by_check == {"AZ_SQL_PUBLIC_ACCESS", "AZ_SQL_NO_AUDITING", "AZ_SQL_NO_TDE"}


def test_sql_scanner_flags_tde_only_on_analytics_server(azure_demo_session):
    findings = AzureSqlScanner(azure_demo_session).run()
    analytics = [f for f in findings if f.resource_name == "sql-analytics"]
    assert [f.check_id for f in analytics] == ["AZ_SQL_NO_TDE"]


def test_sql_scanner_does_not_flag_clean_server(azure_demo_session):
    findings = AzureSqlScanner(azure_demo_session).run()
    assert "sql-staging" not in {f.resource_name for f in findings}


# -- key vault / disks ---------------------------------------------------------

def test_keyvault_scanner_flags_missing_recovery_settings(azure_demo_session):
    findings = AzureKeyVaultScanner(azure_demo_session).run()
    by_check = {f.check_id for f in findings}
    assert by_check == {"AZ_KV_NO_SOFT_DELETE", "AZ_KV_NO_PURGE_PROTECTION"}
    assert all(f.resource_name == "kv-prod-secrets" for f in findings)


def test_disk_scanner_flags_unencrypted_disks(azure_demo_session):
    findings = AzureDiskScanner(azure_demo_session).run()
    unencrypted = [f for f in findings if f.check_id == "AZ_DISK_NO_ENCRYPTION"]
    assert {f.resource_name for f in unencrypted} == {"vm-prod-osdisk", "orphan-disk-2023"}


# -- provider model ------------------------------------------------------------

def test_all_azure_findings_carry_provider_azure(azure_demo_session):
    for scanner_cls in AZURE_SCANNERS:
        for f in scanner_cls(azure_demo_session).run():
            assert f.provider == CloudProvider.AZURE, f"{f.check_id} has wrong provider"
            assert f.to_dict()["provider"] == "azure"


def test_all_azure_findings_have_remediation_and_compliance_or_reference(azure_demo_session):
    for scanner_cls in AZURE_SCANNERS:
        for f in scanner_cls(azure_demo_session).run():
            assert f.remediation, f"{f.check_id} is missing remediation text"
            assert f.compliance or f.references, f"{f.check_id} has no compliance mapping or references"


def test_orchestrator_provider_filtering():
    azure_only = ScanOrchestrator(provider="azure").run_full_scan("test-az-only")
    assert azure_only.providers == ["azure"]
    assert azure_only.findings
    assert {f.provider for f in azure_only.findings} == {CloudProvider.AZURE}

    aws_only = ScanOrchestrator(provider="aws").run_full_scan("test-aws-only")
    assert aws_only.providers == ["aws"]
    assert {f.provider for f in aws_only.findings} == {CloudProvider.AWS}

    both = ScanOrchestrator(provider="all").run_full_scan("test-both")
    assert both.providers == ["aws", "azure"]
    assert {f.provider for f in both.findings} == {CloudProvider.AWS, CloudProvider.AZURE}
    # "all" is the union of the two single-provider scans.
    assert len(both.findings) == len(azure_only.findings) + len(aws_only.findings)


def test_orchestrator_rejects_unknown_provider():
    import pytest

    with pytest.raises(ValueError):
        ScanOrchestrator(provider="gcp")


def test_risk_engine_computes_per_provider_scores(azure_demo_session):
    from app.scanners.s3_scanner import S3Scanner
    from tests.conftest import FakeDemoSessionManager

    aws_findings = S3Scanner(FakeDemoSessionManager()).run()
    azure_findings = AzureStorageScanner(azure_demo_session).run()
    result = calculate_risk_score(aws_findings + azure_findings)
    assert set(result.provider_scores) == {"aws", "azure"}
    assert all(0 <= s <= 100 for s in result.provider_scores.values())
    # The overall score must be worse than (or equal to) each provider's
    # score: it combines both providers' penalties.
    assert result.score <= min(result.provider_scores.values())


def test_azure_demo_mode_fallback_without_credentials():
    manager = AzureSessionManager()
    assert manager.is_live is False
    findings = AzureStorageScanner(manager).run()
    assert findings  # demo data is used, not an error
    assert all(f.provider == CloudProvider.AZURE for f in findings)


# -- live-fetch normalisation (mocked SDK clients) -----------------------------

class _FakeLiveAzureSessionManager(AzureSessionManager):
    """Pretends to be live and serves canned SDK-shaped objects."""

    def __init__(self, clients):
        super().__init__(subscription_id="00000000-0000-0000-0000-000000000000")
        self._fake_clients = clients

    @property
    def is_live(self) -> bool:
        return True

    def client(self, kind: str):
        return self._fake_clients[kind]


def _fake_storage_account(**kwargs):
    defaults = {
        "name": "livestorageacct",
        "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-live/providers/Microsoft.Storage/storageAccounts/livestorageacct",
        "location": "eastus",
        "allow_blob_public_access": False,
        "enable_https_traffic_only": True,
        "minimum_tls_version": "TLS1_2",
        "encryption": SimpleNamespace(require_infrastructure_encryption=True),
        "network_rule_set": SimpleNamespace(default_action="Deny"),
        "public_network_access": "Disabled",
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def test_storage_scanner_live_fetch_normalises_sdk_objects():
    bad_account = _fake_storage_account(
        allow_blob_public_access=True, enable_https_traffic_only=False
    )
    good_account = _fake_storage_account(name="goodstorageacct")
    fake_client = SimpleNamespace(
        storage_accounts=SimpleNamespace(list=lambda: [bad_account, good_account])
    )
    manager = _FakeLiveAzureSessionManager({"storage": fake_client})

    findings = AzureStorageScanner(manager).run()
    by_name = {}
    for f in findings:
        by_name.setdefault(f.resource_name, set()).add(f.check_id)
    assert by_name["livestorageacct"] == {"AZ_STORAGE_PUBLIC_BLOB", "AZ_STORAGE_HTTPS_ONLY"}
    assert "goodstorageacct" not in by_name


def test_nsg_scanner_live_fetch_handles_prefix_lists():
    fake_rule = SimpleNamespace(
        name="AllowSSH",
        direction="Inbound",
        access="Allow",
        protocol="Tcp",
        source_address_prefix=None,
        source_address_prefixes=["0.0.0.0/0"],
        destination_port_range=None,
        destination_port_ranges=["22"],
    )
    fake_nsg = SimpleNamespace(
        name="nsg-live",
        id="/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-live/providers/Microsoft.Network/networkSecurityGroups/nsg-live",
        location="eastus",
        security_rules=[fake_rule],
    )
    fake_client = SimpleNamespace(
        network_security_groups=SimpleNamespace(list_all=lambda: [fake_nsg])
    )
    manager = _FakeLiveAzureSessionManager({"network": fake_client})

    findings = AzureNetworkScanner(manager).run()
    assert [f.check_id for f in findings] == ["AZ_NSG_SSH_OPEN_WORLD"]


# -- repository provider filter ------------------------------------------------

def test_repository_filters_findings_by_provider(azure_demo_session):
    from app.scanners.s3_scanner import S3Scanner
    from tests.conftest import FakeDemoSessionManager

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine)
    db = session_factory()

    from app.core.orchestrator import ScanReport
    from datetime import datetime, timezone

    report = ScanOrchestrator(provider="all").run_full_scan("test-repo-provider")
    repository.save_scan_report(db, report)

    azure_rows = repository.list_open_findings(db, provider="azure")
    aws_rows = repository.list_open_findings(db, provider="aws")
    assert azure_rows and aws_rows
    assert all(r.provider == "azure" for r in azure_rows)
    assert all(r.provider == "aws" for r in aws_rows)
    assert len(azure_rows) + len(aws_rows) == len(
        repository.list_open_findings(db)
    )

    scan_row = repository.get_scan(db, "test-repo-provider")
    assert set(scan_row.provider_scores) == {"aws", "azure"}
    db.close()


def test_azure_resource_types_are_distinct_from_aws():
    azure_types = {
        ResourceType.AZURE_STORAGE_ACCOUNT,
        ResourceType.AZURE_NSG,
        ResourceType.AZURE_ROLE_ASSIGNMENT,
        ResourceType.AZURE_ROLE_DEFINITION,
        ResourceType.AZURE_SQL_SERVER,
        ResourceType.AZURE_KEY_VAULT,
        ResourceType.AZURE_MANAGED_DISK,
    }
    assert all(t.value.startswith("azure_") for t in azure_types)
