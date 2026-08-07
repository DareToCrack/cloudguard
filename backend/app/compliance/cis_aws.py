"""Mapping of internal check IDs to CIS AWS Foundations Benchmark v3.0 controls.

This is a curated subset covering the checks implemented by CloudGuard's
scanners. A production system would maintain this mapping for every
supported framework (CIS, NIST 800-53, PCI-DSS, SOC 2, ISO 27001, etc.) in a
structured data file; a Python dict is used here for clarity and to keep the
project dependency-free.
"""

from app.core.finding import ComplianceMapping

FRAMEWORK = "CIS AWS Foundations Benchmark v3.0"

CIS_AWS_MAPPING: dict[str, list[ComplianceMapping]] = {
    "S3_PUBLIC_READ": [
        ComplianceMapping(FRAMEWORK, "2.1.1", "Ensure S3 buckets are not publicly accessible"),
    ],
    "S3_PUBLIC_WRITE": [
        ComplianceMapping(FRAMEWORK, "2.1.1", "Ensure S3 buckets are not publicly accessible"),
    ],
    "S3_NO_ENCRYPTION": [
        ComplianceMapping(FRAMEWORK, "2.1.2", "Ensure S3 buckets have server-side encryption enabled"),
    ],
    "S3_NO_VERSIONING": [
        ComplianceMapping(FRAMEWORK, "2.1.3", "Ensure S3 bucket versioning is enabled"),
    ],
    "S3_NO_LOGGING": [
        ComplianceMapping(FRAMEWORK, "2.1.4", "Ensure S3 bucket access logging is enabled"),
    ],
    "S3_BPA_DISABLED": [
        ComplianceMapping(FRAMEWORK, "2.1.5", "Ensure S3 Block Public Access is enabled at the bucket level"),
    ],
    "IAM_NO_MFA_CONSOLE": [
        ComplianceMapping(FRAMEWORK, "1.10", "Ensure MFA is enabled for all IAM users with a console password"),
    ],
    "IAM_ROOT_MFA_DISABLED": [
        ComplianceMapping(FRAMEWORK, "1.5", "Ensure MFA is enabled for the root user"),
    ],
    "IAM_ACCESS_KEY_ROTATION": [
        ComplianceMapping(FRAMEWORK, "1.14", "Ensure access keys are rotated every 90 days or less"),
    ],
    "IAM_UNUSED_CREDENTIALS": [
        ComplianceMapping(FRAMEWORK, "1.12", "Ensure credentials unused for 45 days or more are disabled"),
    ],
    "IAM_ADMIN_POLICY_ATTACHED": [
        ComplianceMapping(FRAMEWORK, "1.16", "Ensure IAM policies with full administrative privileges are not attached to users directly"),
    ],
    "IAM_WEAK_PASSWORD_POLICY": [
        ComplianceMapping(FRAMEWORK, "1.8", "Ensure IAM password policy requires strong passwords"),
    ],
    "SG_SSH_OPEN_WORLD": [
        ComplianceMapping(FRAMEWORK, "5.2", "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22"),
    ],
    "SG_RDP_OPEN_WORLD": [
        ComplianceMapping(FRAMEWORK, "5.3", "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389"),
    ],
    "SG_ALL_TRAFFIC_OPEN": [
        ComplianceMapping(FRAMEWORK, "5.4", "Ensure no security groups allow unrestricted ingress to all ports/protocols"),
    ],
    "SG_DATABASE_PORT_OPEN_WORLD": [
        ComplianceMapping(FRAMEWORK, "5.2", "Ensure no security groups allow unrestricted ingress to database ports"),
    ],
    "RDS_PUBLIC_ACCESS": [
        ComplianceMapping(FRAMEWORK, "2.3.1", "Ensure RDS instances are not publicly accessible"),
    ],
    "RDS_NO_ENCRYPTION": [
        ComplianceMapping(FRAMEWORK, "2.3.2", "Ensure RDS instance encryption is enabled"),
    ],
    "RDS_NO_BACKUP": [
        ComplianceMapping(FRAMEWORK, "2.3.3", "Ensure RDS automated backups are enabled"),
    ],
    "RDS_NO_DELETION_PROTECTION": [
        ComplianceMapping(FRAMEWORK, "2.3.4", "Ensure RDS deletion protection is enabled for production databases"),
    ],
    "CLOUDTRAIL_NOT_MULTI_REGION": [
        ComplianceMapping(FRAMEWORK, "3.1", "Ensure CloudTrail is enabled in all regions"),
    ],
    "CLOUDTRAIL_NO_VALIDATION": [
        ComplianceMapping(FRAMEWORK, "3.2", "Ensure CloudTrail log file validation is enabled"),
    ],
    "CLOUDTRAIL_NOT_ENCRYPTED": [
        ComplianceMapping(FRAMEWORK, "3.5", "Ensure CloudTrail logs are encrypted using KMS"),
    ],
    "CLOUDTRAIL_MISSING": [
        ComplianceMapping(FRAMEWORK, "3.1", "Ensure CloudTrail is enabled in all regions"),
    ],
    "EBS_NOT_ENCRYPTED": [
        ComplianceMapping(FRAMEWORK, "2.2.1", "Ensure EBS volume encryption is enabled"),
    ],
}


def get_compliance_mapping(check_id: str) -> list[ComplianceMapping]:
    return CIS_AWS_MAPPING.get(check_id, [])
