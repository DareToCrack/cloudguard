"""CloudTrail audit logging and EBS encryption scanners.

Grouped in one module since both are relatively small, high-signal checks
around audit trail integrity and data-at-rest encryption.
"""

from __future__ import annotations

from app.compliance.cis_aws import get_compliance_mapping
from app.core.enums import ResourceType, Severity
from app.core.finding import Finding
from app.scanners.base import BaseScanner
from app.scanners.demo_data import DEMO_CLOUDTRAIL_TRAILS, DEMO_EBS_VOLUMES


class CloudTrailScanner(BaseScanner):
    name = "CloudTrail Scanner"
    service = "cloudtrail"

    def run(self) -> list[Finding]:
        trails = self._demo_or_live(self._fetch_live, lambda: DEMO_CLOUDTRAIL_TRAILS)
        findings: list[Finding] = []

        if not trails:
            findings.append(Finding(
                check_id="CLOUDTRAIL_MISSING",
                title="No CloudTrail trail configured for the account",
                description="No CloudTrail trail was found. Without CloudTrail, API "
                             "activity across the account is not being recorded, "
                             "severely limiting incident response and forensic capability.",
                severity=Severity.CRITICAL,
                resource_type=ResourceType.CLOUDTRAIL,
                resource_id="arn:aws:cloudtrail:::none",
                resource_name="none",
                region="global",
                remediation="Create a multi-region CloudTrail trail with log file "
                             "validation and KMS encryption enabled, delivering to a "
                             "dedicated, access-restricted S3 bucket.",
                compliance=get_compliance_mapping("CLOUDTRAIL_MISSING"),
                references=["https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-a-trail-using-the-console-first-time.html"],
            ))
            return findings

        for trail in trails:
            findings.extend(self._evaluate_trail(trail))
        return findings

    def _fetch_live(self) -> list[dict]:
        ct = self.session_manager.client("cloudtrail")
        trails = []
        for t in ct.describe_trails().get("trailList", []):
            status = ct.get_trail_status(Name=t["Name"])
            trails.append({
                "name": t["Name"],
                "region": t.get("HomeRegion", self.session_manager.region),
                "is_multi_region": t.get("IsMultiRegionTrail", False),
                "log_file_validation_enabled": t.get("LogFileValidationEnabled", False),
                "kms_encrypted": bool(t.get("KmsKeyId")),
                "is_logging": status.get("IsLogging", False),
            })
        return trails

    def _evaluate_trail(self, trail: dict) -> list[Finding]:
        findings: list[Finding] = []
        resource_id = f"arn:aws:cloudtrail:{trail['region']}:{{account}}:trail/{trail['name']}"

        if not trail["is_multi_region"]:
            findings.append(self._finding(
                trail, "CLOUDTRAIL_NOT_MULTI_REGION",
                "CloudTrail trail is not multi-region",
                f"Trail '{trail['name']}' only records events in its home region, "
                "creating blind spots for activity in other AWS regions.",
                Severity.HIGH,
                "Enable 'multi-region trail' so API activity is captured account-wide, "
                "including regions you don't normally use.",
                resource_id,
            ))

        if not trail["log_file_validation_enabled"]:
            findings.append(self._finding(
                trail, "CLOUDTRAIL_NO_VALIDATION",
                "CloudTrail log file validation is disabled",
                f"Trail '{trail['name']}' does not have log file integrity validation "
                "enabled, making tampering with log files harder to detect.",
                Severity.MEDIUM,
                "Enable log file validation so CloudTrail generates digest files that "
                "can be used to verify log integrity.",
                resource_id,
            ))

        if not trail["kms_encrypted"]:
            findings.append(self._finding(
                trail, "CLOUDTRAIL_NOT_ENCRYPTED",
                "CloudTrail logs are not encrypted with KMS",
                f"Trail '{trail['name']}' delivers logs to S3 without SSE-KMS "
                "encryption configured.",
                Severity.MEDIUM,
                "Configure the trail to use SSE-KMS encryption with a dedicated CMK, "
                "and restrict key usage via a tightly scoped key policy.",
                resource_id,
            ))

        if not trail["is_logging"]:
            findings.append(self._finding(
                trail, "CLOUDTRAIL_NOT_ENCRYPTED",  # reuse; logging-disabled is critical regardless
                "CloudTrail trail exists but logging is currently stopped",
                f"Trail '{trail['name']}' is configured but is not actively logging "
                "(StopLogging was called or logging has not started).",
                Severity.CRITICAL,
                "Re-enable logging immediately via StartLogging and investigate why "
                "it was stopped, including who made the change.",
                resource_id,
            ))

        return findings

    def _finding(
        self, trail: dict, check_id: str, title: str, description: str,
        severity: Severity, remediation: str, resource_id: str,
    ) -> Finding:
        return Finding(
            check_id=check_id,
            title=title,
            description=description,
            severity=severity,
            resource_type=ResourceType.CLOUDTRAIL,
            resource_id=resource_id,
            resource_name=trail["name"],
            region=trail["region"],
            remediation=remediation,
            evidence={k: v for k, v in trail.items() if k != "name"},
            compliance=get_compliance_mapping(check_id),
            references=["https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html"],
        )


class EBSScanner(BaseScanner):
    name = "EBS Volume Scanner"
    service = "ec2"

    def run(self) -> list[Finding]:
        volumes = self._demo_or_live(self._fetch_live, lambda: DEMO_EBS_VOLUMES)
        findings: list[Finding] = []
        for vol in volumes:
            if not vol["encrypted"]:
                findings.append(Finding(
                    check_id="EBS_NOT_ENCRYPTED",
                    title="EBS volume is not encrypted",
                    description=f"Volume '{vol['volume_id']}' does not have encryption "
                                 "enabled, exposing data at rest if the underlying disk "
                                 "is ever improperly decommissioned or accessed.",
                    severity=Severity.MEDIUM,
                    resource_type=ResourceType.EBS_VOLUME,
                    resource_id=f"arn:aws:ec2:{vol['region']}:{{account}}:volume/{vol['volume_id']}",
                    resource_name=vol["volume_id"],
                    region=vol["region"],
                    remediation="Enable EBS encryption by default at the account/region "
                                 "level, and migrate existing unencrypted volumes via "
                                 "snapshot-copy-with-encryption.",
                    evidence=vol,
                    compliance=get_compliance_mapping("EBS_NOT_ENCRYPTED"),
                    references=["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"],
                ))
        return findings

    def _fetch_live(self) -> list[dict]:
        ec2 = self.session_manager.client("ec2")
        volumes = []
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for v in page["Volumes"]:
                volumes.append({
                    "volume_id": v["VolumeId"],
                    "region": self.session_manager.region,
                    "encrypted": v.get("Encrypted", False),
                    "state": v.get("State", ""),
                })
        return volumes
