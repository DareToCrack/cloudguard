"""RDS database misconfiguration scanner."""

from __future__ import annotations

from app.compliance.cis_aws import get_compliance_mapping
from app.core.enums import ResourceType, Severity
from app.core.finding import Finding
from app.scanners.base import BaseScanner
from app.scanners.demo_data import DEMO_RDS_INSTANCES


class RDSScanner(BaseScanner):
    name = "RDS Scanner"
    service = "rds"

    def run(self) -> list[Finding]:
        instances = self._demo_or_live(self._fetch_live, lambda: DEMO_RDS_INSTANCES)
        findings: list[Finding] = []
        for db in instances:
            findings.extend(self._evaluate_instance(db))
        return findings

    def _fetch_live(self) -> list[dict]:
        rds = self.session_manager.client("rds")
        instances = []
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                instances.append({
                    "db_instance_id": db["DBInstanceIdentifier"],
                    "engine": db.get("Engine", ""),
                    "region": self.session_manager.region,
                    "publicly_accessible": db.get("PubliclyAccessible", False),
                    "storage_encrypted": db.get("StorageEncrypted", False),
                    "backup_retention_days": db.get("BackupRetentionPeriod", 0),
                    "multi_az": db.get("MultiAZ", False),
                    "deletion_protection": db.get("DeletionProtection", False),
                    "auto_minor_version_upgrade": db.get("AutoMinorVersionUpgrade", False),
                })
        return instances

    def _evaluate_instance(self, db: dict) -> list[Finding]:
        findings: list[Finding] = []
        resource_id = f"arn:aws:rds:{db['region']}:{{account}}:db:{db['db_instance_id']}"

        if db["publicly_accessible"]:
            findings.append(self._finding(
                db, "RDS_PUBLIC_ACCESS",
                "RDS instance is publicly accessible",
                f"Database instance '{db['db_instance_id']}' ({db['engine']}) has a public "
                "endpoint and can be reached directly from the internet.",
                Severity.CRITICAL,
                "Set PubliclyAccessible to false and place the instance in a private "
                "subnet. Access it through a bastion host, VPN, or application tier only.",
                resource_id,
            ))

        if not db["storage_encrypted"]:
            findings.append(self._finding(
                db, "RDS_NO_ENCRYPTION",
                "RDS instance storage is not encrypted",
                f"Database instance '{db['db_instance_id']}' does not have storage "
                "encryption (KMS) enabled, exposing data at rest.",
                Severity.HIGH,
                "Enable storage encryption. Existing unencrypted instances typically "
                "require a snapshot-and-restore into a new encrypted instance.",
                resource_id,
            ))

        if db["backup_retention_days"] == 0:
            findings.append(self._finding(
                db, "RDS_NO_BACKUP",
                "RDS automated backups are disabled",
                f"Database instance '{db['db_instance_id']}' has a backup retention "
                "period of 0 days, meaning automated backups are effectively disabled.",
                Severity.HIGH,
                "Set the backup retention period to at least 7 days (30+ for "
                "production/critical systems) and validate restore procedures periodically.",
                resource_id,
            ))

        if not db["deletion_protection"]:
            findings.append(self._finding(
                db, "RDS_NO_DELETION_PROTECTION",
                "RDS deletion protection is disabled",
                f"Database instance '{db['db_instance_id']}' does not have deletion "
                "protection enabled, allowing accidental or malicious deletion.",
                Severity.LOW,
                "Enable deletion protection for all production database instances.",
                resource_id,
            ))

        return findings

    def _finding(
        self, db: dict, check_id: str, title: str, description: str,
        severity: Severity, remediation: str, resource_id: str,
    ) -> Finding:
        return Finding(
            check_id=check_id,
            title=title,
            description=description,
            severity=severity,
            resource_type=ResourceType.RDS_INSTANCE,
            resource_id=resource_id,
            resource_name=db["db_instance_id"],
            region=db["region"],
            remediation=remediation,
            evidence={k: v for k, v in db.items() if k != "db_instance_id"},
            compliance=get_compliance_mapping(check_id),
            references=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html"],
        )
