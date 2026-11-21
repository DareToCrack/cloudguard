"""Azure Key Vault misconfiguration scanner."""

from __future__ import annotations

from app.compliance.cis_azure import get_compliance_mapping
from app.core.enums import CloudProvider, ResourceType, Severity
from app.core.finding import Finding
from app.scanners.azure_common import (
    azure_resource_id,
    effective_subscription_id,
    resource_group_from_id,
)
from app.scanners.azure_demo_data import DEMO_AZURE_KEY_VAULTS
from app.scanners.base import BaseScanner


class AzureKeyVaultScanner(BaseScanner):
    name = "Azure Key Vault Scanner"
    service = "azure_keyvault"
    provider = "azure"

    def run(self) -> list[Finding]:
        vaults = self._demo_or_live(self._fetch_live, self._fetch_demo)
        findings: list[Finding] = []
        for vault in vaults:
            findings.extend(self._evaluate_vault(vault))
        return findings

    # -- data sources ---------------------------------------------------

    def _fetch_demo(self) -> list[dict]:
        return DEMO_AZURE_KEY_VAULTS

    def _fetch_live(self) -> list[dict]:
        """Pull real Key Vault configuration via the Azure SDK,
        normalised into the same shape produced by the demo dataset.

        Note: soft delete has been mandatory for new vaults since 2023,
        so the API may return None for it - that is treated as enabled.
        Purge protection is still opt-in, so None means disabled.
        """
        keyvault = self.session_manager.client("keyvault")
        results = []
        for vault in keyvault.vaults.list_by_subscription():
            props = vault.properties
            soft_delete = getattr(props, "enable_soft_delete", None)
            purge_protection = getattr(props, "enable_purge_protection", None)
            results.append({
                "name": vault.name,
                "resource_group": resource_group_from_id(vault.id or ""),
                "location": vault.location or "unknown",
                "soft_delete_enabled": True if soft_delete is None else bool(soft_delete),
                "purge_protection_enabled": bool(purge_protection),
            })
        return results

    # -- checks -----------------------------------------------------------

    def _evaluate_vault(self, vault: dict) -> list[Finding]:
        findings: list[Finding] = []
        subscription_id = effective_subscription_id(self.session_manager)
        resource_id = azure_resource_id(
            subscription_id,
            vault["resource_group"],
            "Microsoft.KeyVault",
            "vaults",
            vault["name"],
        )

        if not vault["soft_delete_enabled"]:
            findings.append(self._make_finding(
                vault, "AZ_KV_NO_SOFT_DELETE",
                "Key Vault soft delete is disabled",
                f"Key Vault '{vault['name']}' does not have soft delete "
                "enabled. Deleted keys, secrets, and certificates are "
                "destroyed immediately instead of being recoverable for "
                "90 days.",
                Severity.MEDIUM,
                "Enable soft delete on the vault. Soft delete is mandatory "
                "for new vaults and cannot be disabled once enabled.",
                resource_id,
            ))

        if not vault["purge_protection_enabled"]:
            findings.append(self._make_finding(
                vault, "AZ_KV_NO_PURGE_PROTECTION",
                "Key Vault purge protection is disabled",
                f"Key Vault '{vault['name']}' does not have purge protection "
                "enabled. A soft-deleted vault (or its contents) can still "
                "be permanently purged before the retention period ends.",
                Severity.MEDIUM,
                "Enable purge protection on the vault. Purge protection "
                "cannot be disabled once enabled.",
                resource_id,
            ))

        return findings

    def _make_finding(
        self, vault: dict, check_id: str, title: str, description: str,
        severity: Severity, remediation: str, resource_id: str,
    ) -> Finding:
        return Finding(
            check_id=check_id,
            title=title,
            description=description,
            severity=severity,
            provider=CloudProvider.AZURE,
            resource_type=ResourceType.AZURE_KEY_VAULT,
            resource_id=resource_id,
            resource_name=vault["name"],
            region=vault["location"],
            remediation=remediation,
            evidence={k: v for k, v in vault.items() if k != "name"},
            compliance=get_compliance_mapping(check_id),
            references=[
                "https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview",
            ],
        )
