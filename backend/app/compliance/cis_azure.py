"""Mapping of internal Azure check IDs to CIS Microsoft Azure Foundations
Benchmark v3.0.0 controls.

Control IDs and titles follow the published v3.0.0 benchmark
(09-05-2024), verified against the benchmark's table of contents:
section 3 covers Security (3.3 Key Vault), section 4 Storage Accounts,
section 5 Database Services, section 7 Networking, and section 8
Virtual Machines.

Two deliberate gaps:

- The RBAC scope checks (``AZ_RBAC_BROAD_OWNER``,
  ``AZ_RBAC_BROAD_CONTRIBUTOR``, ``AZ_ROLE_UNUSED_CUSTOM``) have no
  direct v3.0.0 control. Control 2.23 ("Ensure That No Custom
  Subscription Administrator Roles Exist") covers custom roles *with
  administrative permissions*, not broad built-in role assignments or
  unused custom roles, so mapping to it would be misleading. Those
  findings carry Microsoft Learn references instead of a CIS mapping.
- Disk encryption maps to 8.3/8.4, which are written around Customer
  Managed Keys. A disk with encryption disabled entirely fails both
  controls a fortiori, so the mapping is the closest available control
  for the check.
"""

from app.core.finding import ComplianceMapping

FRAMEWORK = "CIS Microsoft Azure Foundations Benchmark v3.0.0"

CIS_AZURE_MAPPING: dict[str, list[ComplianceMapping]] = {
    "AZ_STORAGE_PUBLIC_BLOB": [
        ComplianceMapping(FRAMEWORK, "4.17", "Ensure that 'Allow Blob Anonymous Access' is set to 'Disabled'"),
    ],
    "AZ_STORAGE_HTTPS_ONLY": [
        ComplianceMapping(FRAMEWORK, "4.1", "Ensure that 'Secure transfer required' is set to 'Enabled'"),
    ],
    "AZ_STORAGE_MIN_TLS": [
        ComplianceMapping(FRAMEWORK, "4.15", "Ensure the 'Minimum TLS version' for storage accounts is set to 'Version 1.2'"),
    ],
    "AZ_STORAGE_NO_ENCRYPTION": [
        ComplianceMapping(FRAMEWORK, "4.2", "Ensure that 'Enable Infrastructure Encryption' for Each Storage Account in Azure Storage is Set to 'enabled'"),
    ],
    "AZ_STORAGE_NETWORK_OPEN": [
        ComplianceMapping(FRAMEWORK, "4.7", "Ensure Default Network Access Rule for Storage Accounts is Set to Deny"),
    ],
    "AZ_NSG_SSH_OPEN_WORLD": [
        ComplianceMapping(FRAMEWORK, "7.2", "Ensure that SSH access from the Internet is evaluated and restricted"),
    ],
    "AZ_NSG_RDP_OPEN_WORLD": [
        ComplianceMapping(FRAMEWORK, "7.1", "Ensure that RDP access from the Internet is evaluated and restricted"),
    ],
    "AZ_NSG_ANY_PORT_OPEN_WORLD": [
        ComplianceMapping(FRAMEWORK, "7.1", "Ensure that RDP access from the Internet is evaluated and restricted"),
        ComplianceMapping(FRAMEWORK, "7.2", "Ensure that SSH access from the Internet is evaluated and restricted"),
    ],
    "AZ_SQL_PUBLIC_ACCESS": [
        ComplianceMapping(FRAMEWORK, "5.1.7", "Ensure Public Network Access is Disabled for SQL Servers"),
    ],
    "AZ_SQL_NO_AUDITING": [
        ComplianceMapping(FRAMEWORK, "5.1.1", "Ensure that 'Auditing' is set to 'On'"),
    ],
    "AZ_SQL_NO_TDE": [
        ComplianceMapping(FRAMEWORK, "5.1.5", "Ensure that 'Data encryption' is set to 'On' on a SQL Database"),
    ],
    "AZ_KV_NO_SOFT_DELETE": [
        ComplianceMapping(FRAMEWORK, "3.3.5", "Ensure the Key Vault is Recoverable"),
    ],
    "AZ_KV_NO_PURGE_PROTECTION": [
        ComplianceMapping(FRAMEWORK, "3.3.5", "Ensure the Key Vault is Recoverable"),
    ],
    "AZ_DISK_NO_ENCRYPTION": [
        ComplianceMapping(FRAMEWORK, "8.3", "Ensure that 'OS and Data' disks are encrypted with Customer Managed Key (CMK)"),
        ComplianceMapping(FRAMEWORK, "8.4", "Ensure that 'Unattached disks' are encrypted with 'Customer Managed Key' (CMK)"),
    ],
}


def get_compliance_mapping(check_id: str) -> list[ComplianceMapping]:
    return CIS_AZURE_MAPPING.get(check_id, [])
