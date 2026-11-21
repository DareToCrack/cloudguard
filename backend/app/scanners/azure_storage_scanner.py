"""Azure Storage Account misconfiguration scanner."""

from __future__ import annotations

from app.compliance.cis_azure import get_compliance_mapping
from app.core.enums import CloudProvider, ResourceType, Severity
from app.core.finding import Finding
from app.scanners.azure_common import (
    azure_resource_id,
    effective_subscription_id,
    resource_group_from_id,
)
from app.scanners.azure_demo_data import DEMO_AZURE_STORAGE_ACCOUNTS
from app.scanners.base import BaseScanner


class AzureStorageScanner(BaseScanner):
    name = "Azure Storage Account Scanner"
    service = "azure_storage"
    provider = "azure"

    def run(self) -> list[Finding]:
        accounts = self._demo_or_live(self._fetch_live, self._fetch_demo)
        findings: list[Finding] = []
        for account in accounts:
            findings.extend(self._evaluate_account(account))
        return findings

    # -- data sources ---------------------------------------------------

    def _fetch_demo(self) -> list[dict]:
        return DEMO_AZURE_STORAGE_ACCOUNTS

    def _fetch_live(self) -> list[dict]:
        """Pull real storage account configuration via the Azure SDK.

        Each account's properties are normalised into the same shape
        produced by the demo dataset so `_evaluate_account` is identical
        in both modes.
        """
        storage = self.session_manager.client("storage")
        results = []
        for acct in storage.storage_accounts.list():
            enc = acct.encryption
            network_rules = acct.network_rule_set
            results.append(
                {
                    "name": acct.name,
                    "resource_group": resource_group_from_id(acct.id or ""),
                    "location": acct.location or "unknown",
                    "allow_blob_public_access": bool(
                        getattr(acct, "allow_blob_public_access", False)
                    ),
                    "https_only": bool(getattr(acct, "enable_https_traffic_only", False)),
                    "minimum_tls_version": getattr(acct, "minimum_tls_version", None) or "TLS1_0",
                    "infrastructure_encryption": bool(
                        enc.require_infrastructure_encryption if enc else False
                    ),
                    "network_default_action": (
                        network_rules.default_action if network_rules else "Allow"
                    ),
                    "public_network_access": getattr(acct, "public_network_access", None)
                    or "Enabled",
                }
            )
        return results

    # -- checks -----------------------------------------------------------

    def _evaluate_account(self, account: dict) -> list[Finding]:
        findings: list[Finding] = []
        subscription_id = effective_subscription_id(self.session_manager)
        resource_id = azure_resource_id(
            subscription_id,
            account["resource_group"],
            "Microsoft.Storage",
            "storageAccounts",
            account["name"],
        )
        intended_public = account.get("intended_public", False)

        if account["allow_blob_public_access"] and not intended_public:
            findings.append(self._make_finding(
                account, "AZ_STORAGE_PUBLIC_BLOB",
                "Storage account allows anonymous blob access",
                f"Storage account '{account['name']}' has 'Allow Blob Anonymous "
                "Access' enabled, so any blob container configured for public "
                "access can be read anonymously over the internet.",
                Severity.HIGH,
                "Set 'Allow Blob Anonymous Access' to Disabled unless the "
                "account intentionally hosts public content. Prefer private "
                "containers with SAS tokens or Entra ID authentication.",
                resource_id,
            ))

        if not account["https_only"]:
            findings.append(self._make_finding(
                account, "AZ_STORAGE_HTTPS_ONLY",
                "Storage account does not require secure transfer (HTTPS)",
                f"Storage account '{account['name']}' allows plain-HTTP "
                "requests, so data can be transmitted in clear text.",
                Severity.MEDIUM,
                "Enable 'Secure transfer required' (enableHttpsTrafficOnly) "
                "so all requests to the account must use HTTPS.",
                resource_id,
            ))

        if account["minimum_tls_version"] != "TLS1_2":
            findings.append(self._make_finding(
                account, "AZ_STORAGE_MIN_TLS",
                "Storage account allows TLS versions older than 1.2",
                f"Storage account '{account['name']}' has minimum TLS version "
                f"'{account['minimum_tls_version']}'. TLS 1.0/1.1 have known "
                "vulnerabilities and should be disabled.",
                Severity.MEDIUM,
                "Set the storage account's minimum TLS version to TLS1_2.",
                resource_id,
            ))

        if not account["infrastructure_encryption"]:
            findings.append(self._make_finding(
                account, "AZ_STORAGE_NO_ENCRYPTION",
                "Storage account infrastructure encryption is not enabled",
                f"Storage account '{account['name']}' does not have "
                "infrastructure encryption (double encryption) enabled. "
                "Service-level encryption is on by default; infrastructure "
                "encryption adds a second, platform-managed layer.",
                Severity.LOW,
                "Enable infrastructure encryption when creating new storage "
                "accounts (it cannot be enabled on an existing account - "
                "migrate data to a new account to remediate).",
                resource_id,
            ))

        if account["network_default_action"] == "Allow":
            findings.append(self._make_finding(
                account, "AZ_STORAGE_NETWORK_OPEN",
                "Storage account default network access rule is Allow",
                f"Storage account '{account['name']}' allows network access "
                "from all networks by default. Combined with public network "
                "access, any internet client can reach the account endpoint.",
                Severity.MEDIUM,
                "Set the default network access rule to Deny and allow only "
                "selected virtual networks / IP ranges (or disable public "
                "network access entirely and use private endpoints).",
                resource_id,
            ))

        return findings

    def _make_finding(
        self, account: dict, check_id: str, title: str, description: str,
        severity: Severity, remediation: str, resource_id: str,
    ) -> Finding:
        return Finding(
            check_id=check_id,
            title=title,
            description=description,
            severity=severity,
            provider=CloudProvider.AZURE,
            resource_type=ResourceType.AZURE_STORAGE_ACCOUNT,
            resource_id=resource_id,
            resource_name=account["name"],
            region=account["location"],
            remediation=remediation,
            evidence={k: v for k, v in account.items() if k != "name"},
            compliance=get_compliance_mapping(check_id),
            references=[
                "https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure",
            ],
        )
