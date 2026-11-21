"""Azure RBAC (authorization) misconfiguration scanner.

Checks role assignments and custom role definitions at subscription
scope. This scanner uses only Azure Resource Manager (ARM) APIs, which
are readable with the built-in Reader role.

Deliberately out of scope: service-principal credential age. That data
lives in Microsoft Graph, not ARM, and reading it requires
``Application.Read.All`` (or similar) Graph permissions that go well
beyond the read-only Reader RBAC role this scanner is designed around.
See docs/FUTURE_WORK.md.
"""

from __future__ import annotations

from app.compliance.cis_azure import get_compliance_mapping
from app.core.enums import CloudProvider, ResourceType, Severity
from app.core.finding import Finding
from app.scanners.azure_common import effective_subscription_id, subscription_scope
from app.scanners.azure_demo_data import (
    DEMO_AZURE_ROLE_ASSIGNMENTS,
    DEMO_AZURE_ROLE_DEFINITIONS,
)
from app.scanners.base import (
    AZURE_ROLE_CONTRIBUTOR_ID,
    AZURE_ROLE_OWNER_ID,
    BaseScanner,
)

# Built-in role definition IDs we recognise without an extra lookup.
# The live fetch also builds a full ID -> name map from the subscription's
# role definitions, so unknown built-in roles still resolve.
KNOWN_ROLE_NAMES = {
    AZURE_ROLE_OWNER_ID: "Owner",
    AZURE_ROLE_CONTRIBUTOR_ID: "Contributor",
    "acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
}


class AzureAuthorizationScanner(BaseScanner):
    name = "Azure Authorization (RBAC) Scanner"
    service = "azure_authorization"
    provider = "azure"

    def run(self) -> list[Finding]:
        assignments, definitions = self._demo_or_live(self._fetch_live, self._fetch_demo)
        findings: list[Finding] = []
        findings.extend(self._evaluate_assignments(assignments))
        findings.extend(self._evaluate_definitions(definitions, assignments))
        return findings

    # -- data sources ---------------------------------------------------

    def _fetch_demo(self) -> tuple[list[dict], list[dict]]:
        return DEMO_AZURE_ROLE_ASSIGNMENTS, DEMO_AZURE_ROLE_DEFINITIONS

    def _fetch_live(self) -> tuple[list[dict], list[dict]]:
        """Pull real role assignments and definitions via the Azure SDK,
        normalised into the same shape produced by the demo dataset."""
        authz = self.session_manager.client("authorization")
        scope = subscription_scope(self.session_manager.subscription_id)

        # ID -> display name map for every role definition in scope.
        role_names: dict[str, str] = dict(KNOWN_ROLE_NAMES)
        definitions: list[dict] = []
        for d in authz.role_definitions.list(scope):
            role_id = (d.id or "").rsplit("/", 1)[-1]
            role_names[role_id] = d.role_name
            if d.role_type == "CustomRole":
                definitions.append({
                    "id": d.id,
                    "name": d.role_name,
                    "role_type": d.role_type,
                    "assignable_scopes": list(d.assignable_scopes or []),
                    "assigned_count": 0,  # filled in below
                })

        assignments: list[dict] = []
        for a in authz.role_assignments.list_for_subscription():
            role_id = (a.role_definition_id or "").rsplit("/", 1)[-1]
            assignments.append({
                "id": a.id,
                "principal_id": a.principal_id,
                "principal_type": a.principal_type,
                "principal_display_name": None,  # resolving names needs MS Graph
                "role_definition_id": role_id,
                "role_name": role_names.get(role_id, role_id),
                "scope": a.scope,
            })

        # Count how many assignments reference each custom role definition.
        for definition in definitions:
            def_id = definition["id"].rsplit("/", 1)[-1]
            definition["assigned_count"] = sum(
                1 for a in assignments if a["role_definition_id"] == def_id
            )

        return assignments, definitions

    # -- checks -----------------------------------------------------------

    def _evaluate_assignments(self, assignments: list[dict]) -> list[Finding]:
        findings: list[Finding] = []
        subscription_id = effective_subscription_id(self.session_manager)
        sub_scope = subscription_scope(subscription_id)

        for assignment in assignments:
            # Only subscription-wide assignments are flagged: the same
            # role scoped to a single resource group is a deliberate,
            # bounded grant, not a broad one.
            if assignment["scope"] != sub_scope:
                continue
            principal = (
                assignment.get("principal_display_name")
                or assignment["principal_id"]
            )
            if assignment["role_name"] == "Owner":
                findings.append(Finding(
                    check_id="AZ_RBAC_BROAD_OWNER",
                    title="Owner role assigned at subscription scope",
                    description=f"Principal '{principal}' "
                                f"({assignment['principal_type']}) holds the Owner "
                                "role across the entire subscription, granting full "
                                "control over every resource including access "
                                "management itself.",
                    severity=Severity.HIGH,
                    provider=CloudProvider.AZURE,
                    resource_type=ResourceType.AZURE_ROLE_ASSIGNMENT,
                    resource_id=assignment["id"],
                    resource_name=f"Owner → {principal}",
                    region="global",
                    remediation="Scope the assignment to the specific resource "
                                "group(s) the principal actually manages, or "
                                "replace it with a narrower built-in role. Use "
                                "Privileged Identity Management (PIM) for "
                                "just-in-time elevation instead of standing Owner.",
                    evidence={k: v for k, v in assignment.items()},
                    compliance=get_compliance_mapping("AZ_RBAC_BROAD_OWNER"),
                    references=[
                        "https://learn.microsoft.com/en-us/azure/role-based-access-control/best-practices",
                    ],
                ))
            elif assignment["role_name"] == "Contributor":
                findings.append(Finding(
                    check_id="AZ_RBAC_BROAD_CONTRIBUTOR",
                    title="Contributor role assigned at subscription scope",
                    description=f"Principal '{principal}' "
                                f"({assignment['principal_type']}) holds the "
                                "Contributor role across the entire subscription, "
                                "allowing it to create, modify, or delete any "
                                "resource in the subscription.",
                    severity=Severity.MEDIUM,
                    provider=CloudProvider.AZURE,
                    resource_type=ResourceType.AZURE_ROLE_ASSIGNMENT,
                    resource_id=assignment["id"],
                    resource_name=f"Contributor → {principal}",
                    region="global",
                    remediation="Scope the assignment to the specific resource "
                                "group(s) the principal actually manages, or "
                                "replace it with narrower roles (e.g. per-service "
                                "contributor roles).",
                    evidence={k: v for k, v in assignment.items()},
                    compliance=get_compliance_mapping("AZ_RBAC_BROAD_CONTRIBUTOR"),
                    references=[
                        "https://learn.microsoft.com/en-us/azure/role-based-access-control/best-practices",
                    ],
                ))
        return findings

    def _evaluate_definitions(
        self, definitions: list[dict], assignments: list[dict]
    ) -> list[Finding]:
        findings: list[Finding] = []
        for definition in definitions:
            if definition["role_type"] != "CustomRole":
                continue
            if definition.get("assigned_count", 0) > 0:
                continue
            findings.append(Finding(
                check_id="AZ_ROLE_UNUSED_CUSTOM",
                title="Custom role definition has no assignments",
                description=f"Custom role '{definition['name']}' is not "
                            "assigned to any principal. Unused custom roles "
                            "are dead permissions surface: they can be "
                            "assigned later (possibly by mistake) and they "
                            "make access reviews harder to reason about.",
                severity=Severity.LOW,
                provider=CloudProvider.AZURE,
                resource_type=ResourceType.AZURE_ROLE_DEFINITION,
                resource_id=definition["id"],
                resource_name=definition["name"],
                region="global",
                remediation="Delete the custom role definition if it is no "
                            "longer needed, or document why it is retained.",
                evidence={k: v for k, v in definition.items()},
                compliance=get_compliance_mapping("AZ_ROLE_UNUSED_CUSTOM"),
                references=[
                    "https://learn.microsoft.com/en-us/azure/role-based-access-control/custom-roles",
                ],
            ))
        return findings
