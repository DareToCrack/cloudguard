"""S3 bucket misconfiguration scanner."""

from __future__ import annotations

from app.compliance.cis_aws import get_compliance_mapping
from app.core.enums import ResourceType, Severity
from app.core.finding import Finding
from app.scanners.base import BaseScanner
from app.scanners.demo_data import DEMO_S3_BUCKETS


class S3Scanner(BaseScanner):
    name = "S3 Bucket Scanner"
    service = "s3"

    def run(self) -> list[Finding]:
        buckets = self._demo_or_live(self._fetch_live, self._fetch_demo)
        findings: list[Finding] = []
        for bucket in buckets:
            findings.extend(self._evaluate_bucket(bucket))
        return findings

    # -- data sources ---------------------------------------------------

    def _fetch_demo(self) -> list[dict]:
        return DEMO_S3_BUCKETS

    def _fetch_live(self) -> list[dict]:
        """Pull real bucket configuration via boto3.

        Each bucket requires several sub-calls (ACL, encryption, versioning,
        logging, public access block) which are combined into the same
        shape produced by the demo dataset so `_evaluate_bucket` is
        identical in both modes.
        """
        s3 = self.session_manager.client("s3")
        results = []
        for b in s3.list_buckets().get("Buckets", []):
            name = b["Name"]
            region = self._get_bucket_region(s3, name)
            results.append(
                {
                    "name": name,
                    "region": region,
                    "public_read": self._is_publicly_readable(s3, name),
                    "public_write": self._is_publicly_writable(s3, name),
                    "encryption": self._get_encryption(s3, name),
                    "versioning": self._get_versioning(s3, name),
                    "logging_enabled": self._get_logging(s3, name),
                    "block_public_access": self._get_block_public_access(s3, name),
                }
            )
        return results

    def _get_bucket_region(self, s3, name: str) -> str:
        try:
            loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
            return loc or "us-east-1"
        except Exception:  # noqa: BLE001
            return "unknown"

    def _is_publicly_readable(self, s3, name: str) -> bool:
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("URI", "").endswith("AllUsers") and grant.get("Permission") in (
                    "READ",
                    "FULL_CONTROL",
                ):
                    return True
        except Exception:  # noqa: BLE001
            pass
        return False

    def _is_publicly_writable(self, s3, name: str) -> bool:
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("URI", "").endswith("AllUsers") and grant.get("Permission") in (
                    "WRITE",
                    "FULL_CONTROL",
                ):
                    return True
        except Exception:  # noqa: BLE001
            pass
        return False

    def _get_encryption(self, s3, name: str) -> str | None:
        try:
            enc = s3.get_bucket_encryption(Bucket=name)
            rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
            return rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
        except Exception:  # noqa: BLE001
            return None

    def _get_versioning(self, s3, name: str) -> bool:
        try:
            v = s3.get_bucket_versioning(Bucket=name)
            return v.get("Status") == "Enabled"
        except Exception:  # noqa: BLE001
            return False

    def _get_logging(self, s3, name: str) -> bool:
        try:
            log = s3.get_bucket_logging(Bucket=name)
            return "LoggingEnabled" in log
        except Exception:  # noqa: BLE001
            return False

    def _get_block_public_access(self, s3, name: str) -> bool:
        try:
            pab = s3.get_public_access_block(Bucket=name)
            cfg = pab["PublicAccessBlockConfiguration"]
            return all(cfg.values())
        except Exception:  # noqa: BLE001
            return False

    # -- checks -----------------------------------------------------------

    def _evaluate_bucket(self, bucket: dict) -> list[Finding]:
        findings: list[Finding] = []
        resource_id = f"arn:aws:s3:::{bucket['name']}"
        intended_public = bucket.get("intended_public", False)

        if bucket["public_write"]:
            findings.append(self._make_finding(
                bucket, "S3_PUBLIC_WRITE",
                "S3 bucket allows public write access",
                f"Bucket '{bucket['name']}' grants WRITE or FULL_CONTROL to the AllUsers "
                "group, allowing anyone on the internet to upload, overwrite, or delete objects.",
                Severity.CRITICAL,
                "Remove public WRITE/FULL_CONTROL grants from the bucket ACL and bucket "
                "policy. Enable S3 Block Public Access at the bucket and account level.",
                resource_id,
            ))
        elif bucket["public_read"] and not intended_public:
            findings.append(self._make_finding(
                bucket, "S3_PUBLIC_READ",
                "S3 bucket allows public read access",
                f"Bucket '{bucket['name']}' grants READ or FULL_CONTROL to the AllUsers "
                "group. Any object in this bucket can be read anonymously over the internet.",
                Severity.HIGH,
                "Remove public READ grants unless the bucket is intentionally hosting "
                "public content (e.g. a static website). Enable S3 Block Public Access.",
                resource_id,
            ))

        if not bucket["encryption"]:
            findings.append(self._make_finding(
                bucket, "S3_NO_ENCRYPTION",
                "S3 bucket does not enforce server-side encryption",
                f"Bucket '{bucket['name']}' has no default server-side encryption "
                "configuration (SSE-S3 or SSE-KMS).",
                Severity.MEDIUM,
                "Enable default encryption (SSE-S3 or SSE-KMS) on the bucket via "
                "PutBucketEncryption. Prefer SSE-KMS for sensitive data.",
                resource_id,
            ))

        if not bucket["versioning"]:
            findings.append(self._make_finding(
                bucket, "S3_NO_VERSIONING",
                "S3 bucket versioning is disabled",
                f"Bucket '{bucket['name']}' does not have versioning enabled, increasing "
                "risk of unrecoverable data loss from accidental deletion or overwrite.",
                Severity.LOW,
                "Enable versioning via PutBucketVersioning, and consider adding an MFA "
                "Delete requirement for critical buckets.",
                resource_id,
            ))

        if not bucket["logging_enabled"]:
            findings.append(self._make_finding(
                bucket, "S3_NO_LOGGING",
                "S3 bucket access logging is disabled",
                f"Bucket '{bucket['name']}' does not have server access logging enabled, "
                "limiting forensic visibility into who accessed objects.",
                Severity.LOW,
                "Enable S3 server access logging or, preferably, use CloudTrail S3 data "
                "events for more detailed and queryable audit logs.",
                resource_id,
            ))

        if not bucket["block_public_access"]:
            findings.append(self._make_finding(
                bucket, "S3_BPA_DISABLED",
                "S3 Block Public Access is not fully enabled",
                f"Bucket '{bucket['name']}' does not have all four S3 Block Public Access "
                "settings enabled, leaving a gap that could allow future accidental exposure.",
                Severity.MEDIUM,
                "Enable all four Block Public Access settings at the bucket level "
                "(and ideally at the account level as a guardrail).",
                resource_id,
            ))

        return findings

    def _make_finding(
        self, bucket: dict, check_id: str, title: str, description: str,
        severity: Severity, remediation: str, resource_id: str,
    ) -> Finding:
        return Finding(
            check_id=check_id,
            title=title,
            description=description,
            severity=severity,
            resource_type=ResourceType.S3_BUCKET,
            resource_id=resource_id,
            resource_name=bucket["name"],
            region=bucket["region"],
            remediation=remediation,
            evidence={k: v for k, v in bucket.items() if k != "name"},
            compliance=get_compliance_mapping(check_id),
            references=[
                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
            ],
        )
