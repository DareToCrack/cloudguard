"""Synthetic AWS resource inventory used for demo-mode scans.

This data is intentionally designed to be realistic and to trigger a
representative mix of severities across every scanner so the dashboard,
risk scoring, and reporting can be evaluated without a real AWS account.
Resource IDs follow real AWS ARN/ID formats.
"""

DEMO_ACCOUNT_ID = "123456789012"

DEMO_S3_BUCKETS = [
    {
        "name": "prod-app-logs-2024",
        "region": "us-east-1",
        "public_read": True,
        "public_write": False,
        "encryption": None,
        "versioning": False,
        "logging_enabled": False,
        "block_public_access": False,
    },
    {
        "name": "customer-data-backup",
        "region": "us-east-1",
        "public_read": False,
        "public_write": False,
        "encryption": None,
        "versioning": True,
        "logging_enabled": True,
        "block_public_access": True,
    },
    {
        "name": "static-website-assets",
        "region": "us-west-2",
        "public_read": True,
        "public_write": False,
        "encryption": "AES256",
        "versioning": False,
        "logging_enabled": False,
        "block_public_access": False,
        "intended_public": True,  # e.g. static website hosting - not flagged
    },
    {
        "name": "finance-reports-archive",
        "region": "us-east-1",
        "public_read": False,
        "public_write": False,
        "encryption": "aws:kms",
        "versioning": True,
        "logging_enabled": True,
        "block_public_access": True,
    },
    {
        "name": "terraform-state-prod",
        "region": "us-east-1",
        "public_read": False,
        "public_write": False,
        "encryption": None,
        "versioning": True,
        "logging_enabled": False,
        "block_public_access": True,
    },
    {
        "name": "dev-uploads-scratch",
        "region": "us-east-1",
        "public_read": True,
        "public_write": True,
        "encryption": None,
        "versioning": False,
        "logging_enabled": False,
        "block_public_access": False,
    },
]

DEMO_IAM_USERS = [
    {
        "username": "svc-ci-deploy",
        "mfa_enabled": False,
        "access_keys": [
            {"id": "AKIAEXAMPLE00000001", "age_days": 412, "last_used_days_ago": 2},
        ],
        "console_access": False,
        "attached_policies": ["AdministratorAccess"],
        "inline_policies": [],
    },
    {
        "username": "jsmith",
        "mfa_enabled": True,
        "access_keys": [
            {"id": "AKIAEXAMPLE00000002", "age_days": 40, "last_used_days_ago": 1},
        ],
        "console_access": True,
        "attached_policies": ["PowerUserAccess"],
        "inline_policies": [],
    },
    {
        "username": "root-break-glass",
        "mfa_enabled": False,
        "access_keys": [],
        "console_access": True,
        "attached_policies": [],
        "inline_policies": ["FullAccessInline"],
        "is_root_proxy": True,
    },
    {
        "username": "legacy-app-user",
        "mfa_enabled": False,
        "access_keys": [
            {"id": "AKIAEXAMPLE00000003", "age_days": 730, "last_used_days_ago": 220},
        ],
        "console_access": False,
        "attached_policies": ["AmazonS3FullAccess"],
        "inline_policies": [],
    },
    {
        "username": "analytics-readonly",
        "mfa_enabled": True,
        "access_keys": [
            {"id": "AKIAEXAMPLE00000004", "age_days": 15, "last_used_days_ago": 0},
        ],
        "console_access": True,
        "attached_policies": ["ReadOnlyAccess"],
        "inline_policies": [],
    },
]

DEMO_SECURITY_GROUPS = [
    {
        "group_id": "sg-0a1b2c3d4e5f60001",
        "group_name": "web-prod-sg",
        "region": "us-east-1",
        "vpc_id": "vpc-0aaa1111",
        "attached_to": ["i-0111aaa222bbb333c"],
        "ingress_rules": [
            {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"},
            {"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0"},
        ],
    },
    {
        "group_id": "sg-0a1b2c3d4e5f60002",
        "group_name": "db-prod-sg",
        "region": "us-east-1",
        "vpc_id": "vpc-0aaa1111",
        "attached_to": ["db-prod-main"],
        "ingress_rules": [
            {"protocol": "tcp", "from_port": 3306, "to_port": 3306, "cidr": "0.0.0.0/0"},
        ],
    },
    {
        "group_id": "sg-0a1b2c3d4e5f60003",
        "group_name": "internal-services-sg",
        "region": "us-east-1",
        "vpc_id": "vpc-0aaa1111",
        "attached_to": ["i-0222bbb333ccc444d"],
        "ingress_rules": [
            {"protocol": "tcp", "from_port": 8080, "to_port": 8080, "cidr": "10.0.0.0/16"},
        ],
    },
    {
        "group_id": "sg-0a1b2c3d4e5f60004",
        "group_name": "rdp-admin-sg",
        "region": "us-west-2",
        "vpc_id": "vpc-0bbb2222",
        "attached_to": ["i-0333ccc444ddd555e"],
        "ingress_rules": [
            {"protocol": "tcp", "from_port": 3389, "to_port": 3389, "cidr": "0.0.0.0/0"},
        ],
    },
    {
        "group_id": "sg-0a1b2c3d4e5f60005",
        "group_name": "all-traffic-legacy",
        "region": "us-east-1",
        "vpc_id": "vpc-0aaa1111",
        "attached_to": [],
        "ingress_rules": [
            {"protocol": "-1", "from_port": -1, "to_port": -1, "cidr": "0.0.0.0/0"},
        ],
    },
]

DEMO_RDS_INSTANCES = [
    {
        "db_instance_id": "db-prod-main",
        "engine": "mysql",
        "region": "us-east-1",
        "publicly_accessible": True,
        "storage_encrypted": False,
        "backup_retention_days": 0,
        "multi_az": False,
        "deletion_protection": False,
        "auto_minor_version_upgrade": False,
    },
    {
        "db_instance_id": "db-staging-replica",
        "engine": "postgres",
        "region": "us-east-1",
        "publicly_accessible": False,
        "storage_encrypted": True,
        "backup_retention_days": 7,
        "multi_az": False,
        "deletion_protection": False,
        "auto_minor_version_upgrade": True,
    },
    {
        "db_instance_id": "db-analytics-warehouse",
        "engine": "postgres",
        "region": "us-west-2",
        "publicly_accessible": False,
        "storage_encrypted": True,
        "backup_retention_days": 30,
        "multi_az": True,
        "deletion_protection": True,
        "auto_minor_version_upgrade": True,
    },
]

DEMO_CLOUDTRAIL_TRAILS = [
    {
        "name": "management-events-trail",
        "region": "us-east-1",
        "is_multi_region": False,
        "log_file_validation_enabled": True,
        "kms_encrypted": False,
        "is_logging": True,
    }
]
# Single-region, non-KMS-encrypted trail is a realistic partial-credit
# configuration: logging is happening (so the account isn't blind), but it
# has real gaps worth flagging. Empty list simulates an account with NO
# CloudTrail at all in some demo variants;
# kept non-empty here so the "trail exists but weak config" checks have data too.

DEMO_EBS_VOLUMES = [
    {"volume_id": "vol-0a1111aaa2222bbb3", "region": "us-east-1", "encrypted": False, "state": "in-use"},
    {"volume_id": "vol-0b2222bbb3333ccc4", "region": "us-east-1", "encrypted": True, "state": "in-use"},
    {"volume_id": "vol-0c3333ccc4444ddd5", "region": "us-west-2", "encrypted": False, "state": "available"},
]

DEMO_ACCOUNT_SETTINGS = {
    "root_mfa_enabled": False,
    "password_policy": {
        "minimum_length": 8,
        "requires_symbols": False,
        "requires_numbers": True,
        "max_age_days": None,
        "reuse_prevention": 0,
    },
    "account_alternate_contacts_set": False,
}
