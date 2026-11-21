"""Azure Network Security Group (NSG) misconfiguration scanner."""

from __future__ import annotations

from app.compliance.cis_azure import get_compliance_mapping
from app.core.enums import CloudProvider, ResourceType, Severity
from app.core.finding import Finding
from app.scanners.azure_common import (
    azure_resource_id,
    effective_subscription_id,
    resource_group_from_id,
)
from app.scanners.azure_demo_data import DEMO_AZURE_NSGS
from app.scanners.base import BaseScanner

# Source prefixes that mean "the whole internet" in an NSG rule.
INTERNET_PREFIXES = {"0.0.0.0/0", "0.0.0.0", "*", "Internet"}


def _port_ranges_cover(port_ranges: list[str], port: int) -> bool:
    """True if any of the NSG port-range strings includes `port`.

    Handles single ports ("22"), ranges ("80-443"), comma lists
    ("22,3389"), and the wildcard ("*").
    """
    for entry in port_ranges or []:
        for part in str(entry).split(","):
            part = part.strip()
            if part in ("*", "0-65535"):
                return True
            if "-" in part:
                try:
                    lo, hi = part.split("-", 1)
                    if int(lo) <= port <= int(hi):
                        return True
                except ValueError:
                    continue
            else:
                try:
                    if int(part) == port:
                        return True
                except ValueError:
                    continue
    return False


def _port_ranges_are_wildcard(port_ranges: list[str]) -> bool:
    """True if the port ranges cover every port (\"*\" or 0-65535)."""
    for entry in port_ranges or []:
        for part in str(entry).split(","):
            if part.strip() in ("*", "0-65535"):
                return True
    return False


class AzureNetworkScanner(BaseScanner):
    name = "Azure Network Security Group Scanner"
    service = "azure_network"
    provider = "azure"

    def run(self) -> list[Finding]:
        nsgs = self._demo_or_live(self._fetch_live, self._fetch_demo)
        findings: list[Finding] = []
        for nsg in nsgs:
            findings.extend(self._evaluate_nsg(nsg))
        return findings

    # -- data sources ---------------------------------------------------

    def _fetch_demo(self) -> list[dict]:
        return DEMO_AZURE_NSGS

    def _fetch_live(self) -> list[dict]:
        """Pull real NSG rules via the Azure SDK, normalised into the
        same shape produced by the demo dataset."""
        network = self.session_manager.client("network")
        results = []
        for nsg in network.network_security_groups.list_all():
            rules = []
            for r in nsg.security_rules or []:
                sources = list(getattr(r, "source_address_prefixes", None) or [])
                if getattr(r, "source_address_prefix", None):
                    sources.append(r.source_address_prefix)
                ports = list(getattr(r, "destination_port_ranges", None) or [])
                if getattr(r, "destination_port_range", None):
                    ports.append(r.destination_port_range)
                rules.append({
                    "name": r.name,
                    "direction": r.direction,
                    "access": r.access,
                    "protocol": r.protocol,
                    "source_prefix": sources[0] if len(sources) == 1 else sources,
                    "source_prefixes": sources,
                    "destination_port_ranges": ports,
                })
            results.append({
                "name": nsg.name,
                "resource_group": resource_group_from_id(nsg.id or ""),
                "location": nsg.location or "unknown",
                "rules": rules,
            })
        return results

    # -- checks -----------------------------------------------------------

    def _evaluate_nsg(self, nsg: dict) -> list[Finding]:
        findings: list[Finding] = []
        subscription_id = effective_subscription_id(self.session_manager)
        resource_id = azure_resource_id(
            subscription_id,
            nsg["resource_group"],
            "Microsoft.Network",
            "networkSecurityGroups",
            nsg["name"],
        )

        for rule in nsg["rules"]:
            if rule.get("direction") != "Inbound" or rule.get("access") != "Allow":
                continue
            sources = rule.get("source_prefixes")
            if sources is None:
                sources = [rule.get("source_prefix")]
            if not any(s in INTERNET_PREFIXES for s in sources):
                continue
            ports = rule.get("destination_port_ranges", [])

            # A wildcard rule is reported once as an any-port finding
            # rather than also firing the SSH/RDP checks for the same rule.
            if _port_ranges_are_wildcard(ports):
                findings.append(self._make_finding(
                    nsg, rule, "AZ_NSG_ANY_PORT_OPEN_WORLD",
                    "NSG allows unrestricted inbound access on all ports",
                    f"NSG '{nsg['name']}' rule '{rule['name']}' allows inbound "
                    "traffic from 0.0.0.0/0 on every port, exposing every "
                    "service on associated resources to the internet.",
                    Severity.HIGH,
                    "Restrict the rule to the specific ports and source IP "
                    "ranges the workload actually needs, or remove it.",
                    resource_id,
                ))
                continue

            if _port_ranges_cover(ports, 22):
                findings.append(self._make_finding(
                    nsg, rule, "AZ_NSG_SSH_OPEN_WORLD",
                    "NSG allows SSH (port 22) from the internet",
                    f"NSG '{nsg['name']}' rule '{rule['name']}' allows inbound "
                    "SSH from 0.0.0.0/0. Internet-exposed SSH is a constant "
                    "brute-force target.",
                    Severity.CRITICAL,
                    "Restrict SSH access to known administrator IP ranges, "
                    "or remove public SSH entirely and use Azure Bastion / "
                    "just-in-time VM access.",
                    resource_id,
                ))

            if _port_ranges_cover(ports, 3389):
                findings.append(self._make_finding(
                    nsg, rule, "AZ_NSG_RDP_OPEN_WORLD",
                    "NSG allows RDP (port 3389) from the internet",
                    f"NSG '{nsg['name']}' rule '{rule['name']}' allows inbound "
                    "RDP from 0.0.0.0/0. Internet-exposed RDP is a constant "
                    "brute-force and ransomware target.",
                    Severity.CRITICAL,
                    "Restrict RDP access to known administrator IP ranges, "
                    "or remove public RDP entirely and use Azure Bastion / "
                    "just-in-time VM access.",
                    resource_id,
                ))

        return findings

    def _make_finding(
        self, nsg: dict, rule: dict, check_id: str, title: str, description: str,
        severity: Severity, remediation: str, resource_id: str,
    ) -> Finding:
        return Finding(
            check_id=check_id,
            title=title,
            description=description,
            severity=severity,
            provider=CloudProvider.AZURE,
            resource_type=ResourceType.AZURE_NSG,
            resource_id=resource_id,
            resource_name=nsg["name"],
            region=nsg["location"],
            remediation=remediation,
            evidence={
                "rule_name": rule["name"],
                "protocol": rule.get("protocol"),
                "source_prefix": rule.get("source_prefix"),
                "destination_port_ranges": rule.get("destination_port_ranges"),
            },
            compliance=get_compliance_mapping(check_id),
            references=[
                "https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview",
            ],
        )
