"""EC2 Security Group network exposure scanner."""

from __future__ import annotations

from app.compliance.cis_aws import get_compliance_mapping
from app.core.enums import ResourceType, Severity
from app.core.finding import Finding
from app.scanners.base import BaseScanner
from app.scanners.demo_data import DEMO_SECURITY_GROUPS

WORLD_CIDR = "0.0.0.0/0"
SENSITIVE_PORTS = {
    22: ("SG_SSH_OPEN_WORLD", "SSH", Severity.CRITICAL),
    3389: ("SG_RDP_OPEN_WORLD", "RDP", Severity.CRITICAL),
    3306: ("SG_DATABASE_PORT_OPEN_WORLD", "MySQL", Severity.HIGH),
    5432: ("SG_DATABASE_PORT_OPEN_WORLD", "PostgreSQL", Severity.HIGH),
    1433: ("SG_DATABASE_PORT_OPEN_WORLD", "MSSQL", Severity.HIGH),
    27017: ("SG_DATABASE_PORT_OPEN_WORLD", "MongoDB", Severity.HIGH),
    6379: ("SG_DATABASE_PORT_OPEN_WORLD", "Redis", Severity.HIGH),
    9200: ("SG_DATABASE_PORT_OPEN_WORLD", "Elasticsearch", Severity.HIGH),
}


class SecurityGroupScanner(BaseScanner):
    name = "Security Group Scanner"
    service = "ec2"

    def run(self) -> list[Finding]:
        groups = self._demo_or_live(self._fetch_live, lambda: DEMO_SECURITY_GROUPS)
        findings: list[Finding] = []
        for group in groups:
            findings.extend(self._evaluate_group(group))
        return findings

    def _fetch_live(self) -> list[dict]:
        ec2 = self.session_manager.client("ec2")
        groups = []
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                ingress = []
                for perm in sg.get("IpPermissions", []):
                    protocol = perm.get("IpProtocol", "-1")
                    from_port = perm.get("FromPort", -1)
                    to_port = perm.get("ToPort", -1)
                    for ip_range in perm.get("IpRanges", []):
                        ingress.append({
                            "protocol": protocol, "from_port": from_port,
                            "to_port": to_port, "cidr": ip_range.get("CidrIp"),
                        })
                groups.append({
                    "group_id": sg["GroupId"],
                    "group_name": sg.get("GroupName", ""),
                    "region": self.session_manager.region,
                    "vpc_id": sg.get("VpcId", ""),
                    "attached_to": [],  # would require cross-referencing ENIs
                    "ingress_rules": ingress,
                })
        return groups

    def _evaluate_group(self, group: dict) -> list[Finding]:
        findings: list[Finding] = []
        resource_id = f"arn:aws:ec2:{group['region']}:{{account}}:security-group/{group['group_id']}"
        seen_checks: set[str] = set()

        for rule in group["ingress_rules"]:
            if rule["cidr"] != WORLD_CIDR:
                continue

            # Any-protocol / any-port rule
            if rule["protocol"] == "-1" or (rule["from_port"] in (-1, 0) and rule["to_port"] in (-1, 65535)):
                if "SG_ALL_TRAFFIC_OPEN" not in seen_checks:
                    seen_checks.add("SG_ALL_TRAFFIC_OPEN")
                    findings.append(self._finding(
                        group, "SG_ALL_TRAFFIC_OPEN",
                        "Security group allows unrestricted ingress on all ports/protocols",
                        f"Security group '{group['group_name']}' ({group['group_id']}) "
                        "allows inbound traffic from 0.0.0.0/0 on all ports and protocols.",
                        Severity.CRITICAL,
                        "Restrict ingress rules to specific, required ports and known "
                        "source CIDR ranges. Never allow all-ports/all-protocols from the internet.",
                        resource_id,
                    ))
                continue

            port_range = range(rule["from_port"], rule["to_port"] + 1)
            for port, (check_id, label, severity) in SENSITIVE_PORTS.items():
                if port in port_range and check_id not in seen_checks:
                    seen_checks.add(check_id)
                    findings.append(self._finding(
                        group, check_id,
                        f"Security group exposes {label} (port {port}) to the internet",
                        f"Security group '{group['group_name']}' ({group['group_id']}) "
                        f"allows inbound {label} traffic on port {port} from 0.0.0.0/0.",
                        severity,
                        f"Restrict port {port} ingress to specific known IP ranges (e.g. "
                        "office/VPN CIDRs) or remove the rule and use a bastion/SSM Session "
                        "Manager / VPN for administrative access.",
                        resource_id,
                    ))

        return findings

    def _finding(
        self, group: dict, check_id: str, title: str, description: str,
        severity: Severity, remediation: str, resource_id: str,
    ) -> Finding:
        return Finding(
            check_id=check_id,
            title=title,
            description=description,
            severity=severity,
            resource_type=ResourceType.SECURITY_GROUP,
            resource_id=resource_id,
            resource_name=group["group_name"] or group["group_id"],
            region=group["region"],
            remediation=remediation,
            evidence={
                "group_id": group["group_id"],
                "vpc_id": group["vpc_id"],
                "ingress_rules": group["ingress_rules"],
                "attached_to": group["attached_to"],
            },
            compliance=get_compliance_mapping(check_id),
            references=[
                "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html",
            ],
        )
