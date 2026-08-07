# Security Considerations

This document covers what CloudGuard needs to run against a real AWS
account, and what to think about before doing so.

## Required IAM permissions

CloudGuard is **strictly read-only**. Every AWS API call it makes is a
`Describe*`, `Get*`, or `List*` action — it never creates, modifies, or
deletes anything in the scanned account. Attach this policy to whatever
IAM user/role you use for scanning:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudGuardReadOnlyScan",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",

        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketAcl",
        "s3:GetBucketEncryption",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "s3:GetBucketPublicAccessBlock",

        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:ListAttachedUserPolicies",
        "iam:ListUserPolicies",
        "iam:GetLoginProfile",
        "iam:GetAccountSummary",
        "iam:GetAccountPasswordPolicy",

        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVolumes",

        "rds:DescribeDBInstances",

        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus"
      ],
      "Resource": "*"
    }
  ]
}
```

Recommended: create a **dedicated IAM role** for CloudGuard (rather than
reusing an existing user/role) and, if scanning from outside AWS, use
`sts:AssumeRole` with an external ID rather than long-lived access keys.

## Secrets management

- CloudGuard itself stores no AWS credentials — it relies entirely on the
  standard boto3 credential resolution chain (environment variables,
  `~/.aws/credentials`, instance profile, ECS task role, SSO). This means
  there's no credential material in this codebase or its database to leak.
- `CLOUDGUARD_SECRET_KEY` in `.env` is reserved for future
  session/auth-token signing (see `docs/FUTURE_WORK.md` — authentication
  is not yet implemented). Rotate it and never commit a real value; `.env`
  is git-ignored by default (see `.gitignore`).
- The SQLite database (or PostgreSQL, if configured) stores scan findings
  — including `evidence` fields that may contain resource identifiers,
  IAM usernames, security group rules, etc. Treat the database file/table
  with the same access controls you'd apply to any security tooling
  output: it is itself a map of your account's weaknesses.

## Current authentication status

**This version of CloudGuard has no built-in authentication or
authorization on the API/dashboard.** It's designed to be run locally or
deployed behind your own access control layer (VPN, reverse proxy with
SSO, IP allowlisting, etc.) — the same way you'd treat a Grafana or
internal admin dashboard. Do **not** expose the default configuration
directly to the public internet. `docs/FUTURE_WORK.md` covers what a
production auth layer would add (JWT-based auth scaffolding already
exists in `app/core/config.py` — `secret_key`, `jwt_algorithm`,
`access_token_expire_minutes` — but is not yet wired into the API).

## Threat model notes

- **Scanning account compromise.** If the credentials used for scanning
  are compromised, an attacker gains read-only visibility into the
  scanned account's configuration — meaningful reconnaissance value, but
  no ability to modify anything. Scope credentials to the minimal policy
  above and rotate regularly.
- **CloudGuard's own database as a target.** Because findings describe
  exactly what's misconfigured (e.g. "SSH open to 0.0.0.0/0 on sg-xxx"),
  the database is a prioritized attack roadmap if exfiltrated. Encrypt at
  rest if using PostgreSQL in production, and restrict network access to
  the database.
- **Web app security baseline.** The API sets baseline security headers
  (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`) and
  restricts CORS to configured origins (`CLOUDGUARD_CORS_ORIGINS`). TLS
  termination is expected to happen at a reverse proxy/load balancer in
  front of CloudGuard — it is not implemented in the application itself.
- **Dependency supply chain.** All Python dependencies are pinned in
  `requirements.txt`/`requirements-dev.txt`. Review and update
  periodically; consider `pip-audit` in CI (not currently wired up — see
  `docs/FUTURE_WORK.md`).

## What CloudGuard intentionally does NOT do

- It does not attempt exploitation, penetration testing, or any active
  offensive technique against scanned resources — it is a posture/
  configuration auditor, not a pentest tool.
- It does not modify AWS resources under any circumstance.
- It does not send scan data to any third party or external service —
  all data stays in your own database.
