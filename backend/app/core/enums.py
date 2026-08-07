"""Shared enumerations used across the scanning engine."""

from enum import Enum


class Severity(str, Enum):
    """Finding severity, ordered from least to most critical.

    Numeric weights are used by the risk-scoring engine.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        return {
            Severity.INFO: 1,
            Severity.LOW: 3,
            Severity.MEDIUM: 6,
            Severity.HIGH: 9,
            Severity.CRITICAL: 12,
        }[self]


class ResourceType(str, Enum):
    S3_BUCKET = "s3_bucket"
    IAM_USER = "iam_user"
    IAM_ROLE = "iam_role"
    IAM_POLICY = "iam_policy"
    SECURITY_GROUP = "security_group"
    EC2_INSTANCE = "ec2_instance"
    RDS_INSTANCE = "rds_instance"
    KMS_KEY = "kms_key"
    CLOUDTRAIL = "cloudtrail"
    EBS_VOLUME = "ebs_volume"
    VPC = "vpc"
    LAMBDA_FUNCTION = "lambda_function"
    ACCOUNT = "account"


class FindingStatus(str, Enum):
    OPEN = "open"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    RISK_ACCEPTED = "risk_accepted"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class CloudProvider(str, Enum):
    AWS = "aws"
    # Placeholders for future provider modules (see docs/FUTURE_WORK.md).
    AZURE = "azure"
    GCP = "gcp"
