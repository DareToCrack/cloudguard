"""Azure Managed Disk encryption scanner."""

from __future__ import annotations

from app.compliance.cis_azure import get_compliance_mapping
from app.core.enums import CloudProvider, ResourceType, Severity
from app.core.finding import Finding
from app.scanners.azure_common import (
    azure_resource_id,
    effective_subscription_id,
    resource_group_from_id,
)
from app.scanners.azure_demo_data import DEMO_AZURE_DISKS
from app.scanners.base import BaseScanner


class AzureDiskScanner(BaseScanner):
    name = "Azure Managed Disk Scanner"
    service = "azure_disk"
    provider = "azure"

    def run(self) -> list[Finding]:
        disks = self._demo_or_live(self._fetch_live, self._fetch_demo)
        findings: list[Finding] = []
        for disk in disks:
            if not disk["encryption_enabled"]:
                findings.append(self._make_finding(disk))
        return findings

    # -- data sources ---------------------------------------------------

    def _fetch_demo(self) -> list[dict]:
        return DEMO_AZURE_DISKS

    def _fetch_live(self) -> list[dict]:
        """Pull real disk encryption state via the Azure SDK, normalised
        into the same shape produced by the demo dataset.

        A managed disk counts as encrypted when server-side encryption
        is configured (platform-managed or customer-managed key) or the
        legacy Azure Disk Encryption extension is enabled.
        """
        compute = self.session_manager.client("compute")
        results = []
        for disk in compute.disks.list():
            enc = disk.encryption
            enc_settings = disk.encryption_settings_collection
            encrypted = bool(
                (enc is not None and getattr(enc, "type", None))
                or (enc_settings is not None and enc_settings.enabled)
            )
            results.append({
                "name": disk.name,
                "resource_group": resource_group_from_id(disk.id or ""),
                "location": disk.location or "unknown",
                "disk_state": disk.disk_state or "Unknown",
                "encryption_enabled": encrypted,
                "encryption_type": getattr(enc, "type", None) if enc else None,
            })
        return results

    # -- checks -----------------------------------------------------------

    def _make_finding(self, disk: dict) -> Finding:
        subscription_id = effective_subscription_id(self.session_manager)
        resource_id = azure_resource_id(
            subscription_id,
            disk["resource_group"],
            "Microsoft.Compute",
            "disks",
            disk["name"],
        )
        state_note = (
            " This disk is currently unattached, so it holds data that is "
            "not in active use but is still readable by anyone who can "
            "attach it."
            if disk["disk_state"] == "Unattached"
            else ""
        )
        return Finding(
            check_id="AZ_DISK_NO_ENCRYPTION",
            title="Managed disk encryption at rest is not enabled",
            description=f"Managed disk '{disk['name']}' ({disk['disk_state'].lower()}) "
                        "does not have encryption at rest enabled, exposing "
                        f"its data if the underlying storage is accessed.{state_note}",
            severity=Severity.MEDIUM,
            provider=CloudProvider.AZURE,
            resource_type=ResourceType.AZURE_MANAGED_DISK,
            resource_id=resource_id,
            resource_name=disk["name"],
            region=disk["location"],
            remediation="Enable server-side encryption on the disk "
                        "(platform-managed key by default, or a "
                        "customer-managed key in Key Vault for control over "
                        "key rotation and revocation).",
            evidence={k: v for k, v in disk.items() if k != "name"},
            compliance=get_compliance_mapping("AZ_DISK_NO_ENCRYPTION"),
            references=[
                "https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption-overview",
            ],
        )
