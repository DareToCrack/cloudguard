"""Synthetic Azure resource inventory used for demo-mode scans.

Mirrors `demo_data.py` (AWS): a realistic inventory designed to trigger a
representative mix of severities across every Azure scanner so the
dashboard, risk scoring, and reporting can be evaluated without an Azure
subscription. Resource IDs follow real Azure resource-ID formats.

Each record uses the exact same shape the corresponding scanner's live
fetch produces, so the check logic is identical in both modes.
"""

DEMO_AZURE_SUBSCRIPTION_ID = "a1b2c3d4-1234-4a5b-8c9d-0123456789ab"

DEMO_AZURE_STORAGE_ACCOUNTS = [
    {
        "name": "prodstorageacct",
        "resource_group": "rg-data-prod",
        "location": "eastus",
        "allow_blob_public_access": True,
        "https_only": False,
        "minimum_tls_version": "TLS1_0",
        "infrastructure_encryption": False,
        "network_default_action": "Allow",
        "public_network_access": "Enabled",
    },
    {
        "name": "webstaticassets",
        "resource_group": "rg-web-prod",
        "location": "eastus",
        "allow_blob_public_access": True,
        "https_only": True,
        "minimum_tls_version": "TLS1_2",
        "infrastructure_encryption": True,
        "network_default_action": "Deny",
        "public_network_access": "Enabled",
        "intended_public": True,  # e.g. static website hosting - not flagged
    },
    {
        "name": "backuparchivedata",
        "resource_group": "rg-data-prod",
        "location": "westeurope",
        "allow_blob_public_access": False,
        "https_only": True,
        "minimum_tls_version": "TLS1_2",
        "infrastructure_encryption": False,
        "network_default_action": "Deny",
        "public_network_access": "Disabled",
    },
    {
        "name": "financedocsprod",
        "resource_group": "rg-data-prod",
        "location": "eastus",
        "allow_blob_public_access": False,
        "https_only": True,
        "minimum_tls_version": "TLS1_2",
        "infrastructure_encryption": True,
        "network_default_action": "Deny",
        "public_network_access": "Disabled",
    },
]

DEMO_AZURE_NSGS = [
    {
        "name": "nsg-web-prod",
        "resource_group": "rg-web-prod",
        "location": "eastus",
        "rules": [
            {"name": "AllowSSH", "direction": "Inbound", "access": "Allow",
             "protocol": "Tcp", "source_prefix": "0.0.0.0/0",
             "destination_port_ranges": ["22"]},
            {"name": "AllowHTTPS", "direction": "Inbound", "access": "Allow",
             "protocol": "Tcp", "source_prefix": "0.0.0.0/0",
             "destination_port_ranges": ["443"]},
        ],
    },
    {
        "name": "nsg-admin-rdp",
        "resource_group": "rg-web-prod",
        "location": "eastus",
        "rules": [
            {"name": "AllowRDP", "direction": "Inbound", "access": "Allow",
             "protocol": "Tcp", "source_prefix": "0.0.0.0/0",
             "destination_port_ranges": ["3389"]},
        ],
    },
    {
        "name": "nsg-legacy-all",
        "resource_group": "rg-web-prod",
        "location": "eastus",
        "rules": [
            {"name": "AllowAllInbound", "direction": "Inbound", "access": "Allow",
             "protocol": "*", "source_prefix": "0.0.0.0/0",
             "destination_port_ranges": ["*"]},
        ],
    },
    {
        "name": "nsg-internal",
        "resource_group": "rg-web-prod",
        "location": "eastus",
        "rules": [
            {"name": "AllowAppTier", "direction": "Inbound", "access": "Allow",
             "protocol": "Tcp", "source_prefix": "10.0.0.0/8",
             "destination_port_ranges": ["8080"]},
        ],
    },
]

DEMO_AZURE_ROLE_ASSIGNMENTS = [
    {
        "id": f"/subscriptions/{DEMO_AZURE_SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleAssignments/11111111-1111-4111-8111-111111111111",
        "principal_id": "22222222-2222-4222-8222-222222222222",
        "principal_type": "User",
        "principal_display_name": "alice@contoso.com",
        "role_definition_id": "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
        "role_name": "Owner",
        "scope": f"/subscriptions/{DEMO_AZURE_SUBSCRIPTION_ID}",
    },
    {
        "id": f"/subscriptions/{DEMO_AZURE_SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleAssignments/33333333-3333-4333-8333-333333333333",
        "principal_id": "44444444-4444-4444-8444-444444444444",
        "principal_type": "Group",
        "principal_display_name": "dev-team",
        "role_definition_id": "b24988ac-6180-42a0-ab88-20f7382dd24c",
        "role_name": "Contributor",
        "scope": f"/subscriptions/{DEMO_AZURE_SUBSCRIPTION_ID}",
    },
    {
        "id": f"/subscriptions/{DEMO_AZURE_SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleAssignments/55555555-5555-4555-8555-555555555555",
        "principal_id": "66666666-6666-4666-8666-666666666666",
        "principal_type": "User",
        "principal_display_name": "auditor@contoso.com",
        "role_definition_id": "acdd72a7-3385-48ef-bd42-f606fba81ae7",
        "role_name": "Reader",
        "scope": f"/subscriptions/{DEMO_AZURE_SUBSCRIPTION_ID}",
    },
    {
        "id": f"/subscriptions/{DEMO_AZURE_SUBSCRIPTION_ID}/resourceGroups/rg-web-prod/providers/Microsoft.Authorization/roleAssignments/77777777-7777-4777-8777-777777777777",
        "principal_id": "88888888-8888-4888-8888-888888888888",
        "principal_type": "ServicePrincipal",
        "principal_display_name": "spn-deploy-pipeline",
        "role_definition_id": "b24988ac-6180-42a0-ab88-20f7382dd24c",
        "role_name": "Contributor",
        "scope": f"/subscriptions/{DEMO_AZURE_SUBSCRIPTION_ID}/resourceGroups/rg-web-prod",
    },
]

DEMO_AZURE_ROLE_DEFINITIONS = [
    {
        "id": f"/subscriptions/{DEMO_AZURE_SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleDefinitions/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "name": "CustomDeployer",
        "role_type": "CustomRole",
        "assignable_scopes": [f"/subscriptions/{DEMO_AZURE_SUBSCRIPTION_ID}"],
        "assigned_count": 0,
    },
    {
        "id": f"/subscriptions/{DEMO_AZURE_SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleDefinitions/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "name": "BackupOperator",
        "role_type": "CustomRole",
        "assignable_scopes": [f"/subscriptions/{DEMO_AZURE_SUBSCRIPTION_ID}"],
        "assigned_count": 2,
    },
]

DEMO_AZURE_SQL_SERVERS = [
    {
        "name": "sql-prod-main",
        "resource_group": "rg-data-prod",
        "location": "eastus",
        "public_network_access": "Enabled",
        "auditing_enabled": False,
        "auditing_retention_days": 0,
        "databases": [
            {"name": "appdb", "tde_enabled": False},
            {"name": "reportingdb", "tde_enabled": True},
        ],
    },
    {
        "name": "sql-staging",
        "resource_group": "rg-data-prod",
        "location": "eastus",
        "public_network_access": "Disabled",
        "auditing_enabled": True,
        "auditing_retention_days": 90,
        "databases": [
            {"name": "stagingdb", "tde_enabled": True},
        ],
    },
    {
        "name": "sql-analytics",
        "resource_group": "rg-data-prod",
        "location": "westeurope",
        "public_network_access": "Disabled",
        "auditing_enabled": True,
        "auditing_retention_days": 180,
        "databases": [
            {"name": "warehouse", "tde_enabled": False},
        ],
    },
]

DEMO_AZURE_KEY_VAULTS = [
    {
        "name": "kv-prod-secrets",
        "resource_group": "rg-data-prod",
        "location": "eastus",
        "soft_delete_enabled": False,
        "purge_protection_enabled": False,
    },
    {
        "name": "kv-app-config",
        "resource_group": "rg-web-prod",
        "location": "eastus",
        "soft_delete_enabled": True,
        "purge_protection_enabled": True,
    },
]

DEMO_AZURE_DISKS = [
    {
        "name": "vm-prod-osdisk",
        "resource_group": "rg-web-prod",
        "location": "eastus",
        "disk_state": "Attached",
        "encryption_enabled": False,
        "encryption_type": None,
    },
    {
        "name": "vm-prod-datadisk1",
        "resource_group": "rg-web-prod",
        "location": "eastus",
        "disk_state": "Attached",
        "encryption_enabled": True,
        "encryption_type": "EncryptionAtRestWithPlatformKey",
    },
    {
        "name": "orphan-disk-2023",
        "resource_group": "rg-web-prod",
        "location": "eastus",
        "disk_state": "Unattached",
        "encryption_enabled": False,
        "encryption_type": None,
    },
]
