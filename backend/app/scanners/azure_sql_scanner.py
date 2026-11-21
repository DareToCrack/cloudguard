"""Azure SQL Server misconfiguration scanner."""

from __future__ import annotations

from app.compliance.cis_azure import get_compliance_mapping
from app.core.enums import CloudProvider, ResourceType, Severity
from app.core.finding import Finding
from app.scanners.azure_common import (
    azure_resource_id,
    effective_subscription_id,
    resource_group_from_id,
)
from app.scanners.azure_demo_data import DEMO_AZURE_SQL_SERVERS
from app.scanners.base import BaseScanner


class AzureSqlScanner(BaseScanner):
    name = "Azure SQL Server Scanner"
    service = "azure_sql"
    provider = "azure"

    def run(self) -> list[Finding]:
        servers = self._demo_or_live(self._fetch_live, self._fetch_demo)
        findings: list[Finding] = []
        for server in servers:
            findings.extend(self._evaluate_server(server))
        return findings

    # -- data sources ---------------------------------------------------

    def _fetch_demo(self) -> list[dict]:
        return DEMO_AZURE_SQL_SERVERS

    def _fetch_live(self) -> list[dict]:
        """Pull real SQL server configuration via the Azure SDK,
        normalised into the same shape produced by the demo dataset."""
        sql = self.session_manager.client("sql")
        results = []
        for server in sql.servers.list():
            rg = resource_group_from_id(server.id or "")
            auditing = self._get_auditing(sql, rg, server.name)
            results.append({
                "name": server.name,
                "resource_group": rg,
                "location": server.location or "unknown",
                "public_network_access": getattr(server, "public_network_access", None)
                or "Enabled",
                "auditing_enabled": auditing["enabled"],
                "auditing_retention_days": auditing["retention_days"],
                "databases": self._get_databases(sql, rg, server.name),
            })
        return results

    def _get_auditing(self, sql, resource_group: str, server_name: str) -> dict:
        try:
            policy = sql.server_blob_auditing_policies.get(resource_group, server_name)
            return {
                "enabled": (policy.state or "") == "Enabled",
                "retention_days": policy.retention_days or 0,
            }
        except Exception:  # noqa: BLE001 - no auditing policy configured
            return {"enabled": False, "retention_days": 0}

    def _get_databases(self, sql, resource_group: str, server_name: str) -> list[dict]:
        databases = []
        try:
            db_list = sql.databases.list_by_server(resource_group, server_name)
        except Exception:  # noqa: BLE001
            return databases
        for db in db_list:
            if db.name == "master":
                continue
            databases.append({
                "name": db.name,
                "tde_enabled": self._get_tde(sql, resource_group, server_name, db.name),
            })
        return databases

    def _get_tde(self, sql, resource_group: str, server_name: str, db_name: str) -> bool | None:
        """Tri-state: True/False when the API answers, None when the
        call fails (unknown - not flagged, to avoid false positives)."""
        try:
            tde = sql.transparent_data_encryptions.get(resource_group, server_name, db_name)
            return (tde.status or "") == "Enabled"
        except Exception:  # noqa: BLE001
            return None

    # -- checks -----------------------------------------------------------

    def _evaluate_server(self, server: dict) -> list[Finding]:
        findings: list[Finding] = []
        subscription_id = effective_subscription_id(self.session_manager)
        resource_id = azure_resource_id(
            subscription_id,
            server["resource_group"],
            "Microsoft.Sql",
            "servers",
            server["name"],
        )

        if server["public_network_access"] == "Enabled":
            findings.append(self._make_finding(
                server, "AZ_SQL_PUBLIC_ACCESS",
                "SQL server allows public network access",
                f"SQL server '{server['name']}' has public network access "
                "enabled, so the database endpoint is reachable from the "
                "public internet (subject to firewall rules).",
                Severity.HIGH,
                "Disable public network access and connect via private "
                "endpoints. If public access is genuinely required, restrict "
                "it with firewall rules to known client IP ranges.",
                resource_id,
            ))

        if not server["auditing_enabled"]:
            findings.append(self._make_finding(
                server, "AZ_SQL_NO_AUDITING",
                "SQL server auditing is not enabled",
                f"SQL server '{server['name']}' does not have auditing "
                "enabled, so database activity is not being recorded for "
                "forensic or compliance purposes.",
                Severity.MEDIUM,
                "Enable auditing (server blob auditing policy) with a "
                "retention period of at least 90 days, writing to a "
                "dedicated storage account or Log Analytics workspace.",
                resource_id,
            ))

        unencrypted = [
            db["name"] for db in server.get("databases", [])
            if db.get("tde_enabled") is False
        ]
        if unencrypted:
            findings.append(self._make_finding(
                server, "AZ_SQL_NO_TDE",
                "SQL database transparent data encryption (TDE) is disabled",
                f"SQL server '{server['name']}' has database(s) without "
                f"transparent data encryption enabled: {', '.join(unencrypted)}. "
                "Data at rest in those databases is not encrypted.",
                Severity.MEDIUM,
                "Enable transparent data encryption (TDE) on every database. "
                "TDE is on by default for new databases; existing databases "
                "can be encrypted in place.",
                resource_id,
            ))

        return findings

    def _make_finding(
        self, server: dict, check_id: str, title: str, description: str,
        severity: Severity, remediation: str, resource_id: str,
    ) -> Finding:
        return Finding(
            check_id=check_id,
            title=title,
            description=description,
            severity=severity,
            provider=CloudProvider.AZURE,
            resource_type=ResourceType.AZURE_SQL_SERVER,
            resource_id=resource_id,
            resource_name=server["name"],
            region=server["location"],
            remediation=remediation,
            evidence={k: v for k, v in server.items() if k != "name"},
            compliance=get_compliance_mapping(check_id),
            references=[
                "https://learn.microsoft.com/en-us/azure/azure-sql/database/security-best-practice",
            ],
        )
