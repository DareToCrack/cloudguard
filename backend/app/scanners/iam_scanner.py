"""IAM misconfiguration and identity hygiene scanner."""

from __future__ import annotations

from datetime import datetime, timezone

from app.compliance.cis_aws import get_compliance_mapping
from app.core.enums import ResourceType, Severity
from app.core.finding import Finding
from app.scanners.base import BaseScanner
from app.scanners.demo_data import DEMO_ACCOUNT_SETTINGS, DEMO_IAM_USERS

HIGH_PRIVILEGE_POLICIES = {"AdministratorAccess", "PowerUserAccess"}
ACCESS_KEY_MAX_AGE_DAYS = 90
UNUSED_CREDENTIAL_THRESHOLD_DAYS = 45


class IAMScanner(BaseScanner):
    name = "IAM Scanner"
    service = "iam"

    def run(self) -> list[Finding]:
        users = self._demo_or_live(self._fetch_live_users, lambda: DEMO_IAM_USERS)
        account_settings = self._demo_or_live(
            self._fetch_live_account_settings, lambda: DEMO_ACCOUNT_SETTINGS
        )

        findings: list[Finding] = []
        for user in users:
            findings.extend(self._evaluate_user(user))
        findings.extend(self._evaluate_account(account_settings))
        return findings

    # -- data sources ---------------------------------------------------

    def _fetch_live_users(self) -> list[dict]:
        iam = self.session_manager.client("iam")
        users = []
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for u in page["Users"]:
                username = u["UserName"]
                mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
                keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
                access_keys = []
                for k in keys:
                    age_days = (datetime.now(timezone.utc) - k["CreateDate"]).days
                    last_used = iam.get_access_key_last_used(AccessKeyId=k["AccessKeyId"])
                    last_used_date = last_used.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                    last_used_days_ago = (
                        (datetime.now(timezone.utc) - last_used_date).days
                        if last_used_date else age_days
                    )
                    access_keys.append({
                        "id": k["AccessKeyId"], "age_days": age_days,
                        "last_used_days_ago": last_used_days_ago,
                    })
                attached = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
                inline = iam.list_user_policies(UserName=username)["PolicyNames"]
                try:
                    iam.get_login_profile(UserName=username)
                    console_access = True
                except iam.exceptions.NoSuchEntityException:
                    console_access = False
                users.append({
                    "username": username,
                    "mfa_enabled": len(mfa_devices) > 0,
                    "access_keys": access_keys,
                    "console_access": console_access,
                    "attached_policies": [p["PolicyName"] for p in attached],
                    "inline_policies": inline,
                })
        return users

    def _fetch_live_account_settings(self) -> dict:
        iam = self.session_manager.client("iam")
        summary = iam.get_account_summary()["SummaryMap"]
        try:
            pw_policy = iam.get_account_password_policy()["PasswordPolicy"]
        except iam.exceptions.NoSuchEntityException:
            pw_policy = {}
        return {
            "root_mfa_enabled": summary.get("AccountMFAEnabled", 0) == 1,
            "password_policy": {
                "minimum_length": pw_policy.get("MinimumPasswordLength", 0),
                "requires_symbols": pw_policy.get("RequireSymbols", False),
                "requires_numbers": pw_policy.get("RequireNumbers", False),
                "max_age_days": pw_policy.get("MaxPasswordAge"),
                "reuse_prevention": pw_policy.get("PasswordReusePrevention", 0),
            },
            "account_alternate_contacts_set": True,  # requires Account API; assumed
        }

    # -- checks -----------------------------------------------------------

    def _evaluate_user(self, user: dict) -> list[Finding]:
        findings: list[Finding] = []
        resource_id = f"arn:aws:iam::{{account}}:user/{user['username']}"

        if user["console_access"] and not user["mfa_enabled"]:
            severity = Severity.CRITICAL if user.get("is_root_proxy") else Severity.HIGH
            findings.append(self._finding(
                user, "IAM_NO_MFA_CONSOLE",
                "IAM user has console access without MFA",
                f"User '{user['username']}' can sign in to the AWS Console with a password "
                "but does not have a multi-factor authentication device registered.",
                severity,
                "Require and enforce MFA enrollment for every IAM user with console "
                "access; consider an IAM policy that denies actions when MFA is absent.",
                resource_id,
            ))

        for key in user["access_keys"]:
            if key["age_days"] > ACCESS_KEY_MAX_AGE_DAYS:
                findings.append(self._finding(
                    user, "IAM_ACCESS_KEY_ROTATION",
                    "IAM access key exceeds rotation policy",
                    f"Access key {key['id']} for user '{user['username']}' is "
                    f"{key['age_days']} days old, exceeding the {ACCESS_KEY_MAX_AGE_DAYS}-day "
                    "rotation window.",
                    Severity.MEDIUM,
                    "Rotate the access key and, where possible, replace long-lived keys "
                    "with short-lived credentials via IAM roles / STS / OIDC federation.",
                    resource_id,
                ))
            if key["last_used_days_ago"] > UNUSED_CREDENTIAL_THRESHOLD_DAYS:
                findings.append(self._finding(
                    user, "IAM_UNUSED_CREDENTIALS",
                    "IAM access key unused for an extended period",
                    f"Access key {key['id']} for user '{user['username']}' has not been "
                    f"used in {key['last_used_days_ago']} days.",
                    Severity.LOW,
                    "Deactivate or delete access keys that are no longer in active use "
                    "to reduce the credential attack surface.",
                    resource_id,
                ))

        for policy in user["attached_policies"]:
            if policy in HIGH_PRIVILEGE_POLICIES:
                findings.append(self._finding(
                    user, "IAM_ADMIN_POLICY_ATTACHED",
                    "Highly privileged policy attached directly to IAM user",
                    f"User '{user['username']}' has the '{policy}' managed policy attached "
                    "directly, rather than being granted broad access via a role.",
                    Severity.HIGH,
                    "Attach broad-privilege policies to IAM roles/groups instead of "
                    "individual users, and apply least-privilege, scoped policies per user.",
                    resource_id,
                ))

        return findings

    def _evaluate_account(self, settings: dict) -> list[Finding]:
        findings: list[Finding] = []
        resource_id = "arn:aws:iam::{account}:root"

        if not settings["root_mfa_enabled"]:
            findings.append(Finding(
                check_id="IAM_ROOT_MFA_DISABLED",
                title="Root account does not have MFA enabled",
                description="The AWS account root user does not have a multi-factor "
                             "authentication device configured. The root user has "
                             "unrestricted access to every resource in the account.",
                severity=Severity.CRITICAL,
                resource_type=ResourceType.ACCOUNT,
                resource_id=resource_id,
                resource_name="root",
                region="global",
                remediation="Enable a hardware or virtual MFA device on the root user "
                             "immediately, and avoid using the root user for daily tasks.",
                evidence=settings,
                compliance=get_compliance_mapping("IAM_ROOT_MFA_DISABLED"),
                references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html"],
            ))

        pw = settings["password_policy"]
        weak = (
            pw.get("minimum_length", 0) < 14
            or not pw.get("requires_symbols")
            or not pw.get("requires_numbers")
            or (pw.get("reuse_prevention") or 0) < 5
        )
        if weak:
            findings.append(Finding(
                check_id="IAM_WEAK_PASSWORD_POLICY",
                title="Account password policy does not meet security baseline",
                description="The IAM account password policy does not require a "
                             "sufficiently long/complex password or does not prevent "
                             "password reuse.",
                severity=Severity.MEDIUM,
                resource_type=ResourceType.ACCOUNT,
                resource_id=resource_id,
                resource_name="password-policy",
                region="global",
                remediation="Set minimum length to 14+, require symbols and numbers, "
                             "and set password reuse prevention to at least 5.",
                evidence=pw,
                compliance=get_compliance_mapping("IAM_WEAK_PASSWORD_POLICY"),
                references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"],
            ))

        return findings

    def _finding(
        self, user: dict, check_id: str, title: str, description: str,
        severity: Severity, remediation: str, resource_id: str,
    ) -> Finding:
        return Finding(
            check_id=check_id,
            title=title,
            description=description,
            severity=severity,
            resource_type=ResourceType.IAM_USER,
            resource_id=resource_id,
            resource_name=user["username"],
            region="global",
            remediation=remediation,
            evidence={k: v for k, v in user.items() if k != "username"},
            compliance=get_compliance_mapping(check_id),
            references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"],
        )
