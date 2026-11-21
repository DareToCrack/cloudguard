# Limitations, Assumptions & Future Work

Honest accounting of what this project is and isn't, written the way an
engineering team would document it for the next person picking it up.

## Current limitations

- **AWS and Azure only.** No GCP scanning yet, though the provider model
  (`CloudProvider` enum, per-provider scanner registries,
  provider-agnostic `Finding` shape) makes adding a provider additive
  rather than a rewrite.
- **12 services scanned**, not the full AWS/Azure surface. AWS coverage
  is: S3, IAM, EC2 Security Groups, RDS, CloudTrail, EBS. Notably absent:
  Lambda, KMS key policies, VPC flow logs, GuardDuty/Config integration,
  ECS/EKS, Secrets Manager, WAF. Azure coverage is: Storage Accounts,
  Network Security Groups, RBAC role assignments, SQL Servers, Key
  Vaults, Managed Disks. Notably absent: Azure AD/Entra ID settings
  (needs Microsoft Graph), AKS, Azure Firewall, App Service, Azure
  Monitor / Microsoft Sentinel integration. These are the natural next
  scanners to add (see below) — the scanner interface is designed to
  make each one a self-contained module.
- **No service-principal credential-age check for Azure.** Detecting
  stale Azure service-principal credentials requires Microsoft Graph
  (`Application.Read.All` / `Directory.Read.All`), which is a separate
  permission surface from the ARM Reader role CloudGuard otherwise needs.
  Adding it would force every user to grant Entra ID read access just to
  scan ARM resources, so it was deliberately left out. See
  `app/scanners/azure_authorization_scanner.py` for the full reasoning.
- **No authentication on the API/dashboard.** See `docs/SECURITY.md`.
  Config scaffolding exists (`secret_key`, JWT settings) but isn't wired
  into any middleware yet.
- **Live-mode Security Group scanner doesn't resolve `attached_to`.**
  Determining which ENIs/instances use a given security group requires
  additional `describe_network_interfaces` calls that aren't implemented
  yet; the field is present in the data model and populated in demo mode,
  but empty in live mode.
- **Azure live mode doesn't resolve role-assignment principal names.**
  Principal display names need Microsoft Graph (see above); live-mode
  RBAC findings therefore show principal IDs. Demo mode includes names.
- **System-assigned managed identity isn't always auto-detected.**
  CloudGuard's Azure credential pre-check looks for env vars, the `az`
  CLI, and a reachable instance metadata endpoint; if the metadata
  endpoint isn't reachable from the process, Azure falls back to demo
  mode even when a managed identity exists (see
  `docs/SECURITY.md#azure-permissions`).
- **Background scan endpoint (`POST /api/scans`) uses an in-process
  dict** to track scan state (`_SCAN_STATE` in `routes_scans.py`), which
  does not survive an API process restart and doesn't work across
  multiple API replicas. Fine for a single-process deployment; not fine
  for horizontal scaling.
- **SQLite by default.** Works well for a single-user/demo deployment;
  under concurrent writes from multiple scan processes, SQLite's
  file-level locking becomes a bottleneck. `DATABASE_URL` is already
  swappable to PostgreSQL with no code changes (SQLAlchemy handles both),
  but this hasn't been load-tested.
- **No re-opening logic for resolved findings.** If a finding is marked
  `resolved` but the underlying misconfiguration is still present on the
  next scan, CloudGuard currently does not automatically flip it back to
  `open` — the repository layer only updates `last_seen_at` for findings
  it finds still open. A production system would likely want: "if a
  finding was marked resolved but is detected again on a later scan,
  re-open it and flag that the fix didn't stick."
- **Multi-region scanning is not automatic.** The orchestrator scans one
  region per invocation (`--region` flag / `region` field). Scanning all
  regions in one pass would mean looping the orchestrator per region and
  merging results — straightforward, but not implemented.
- **Compliance mapping covers two frameworks** (CIS AWS Foundations
  Benchmark v3.0 and CIS Microsoft Azure Foundations Benchmark v3.0.0,
  partial in both cases — the controls corresponding to implemented
  checks). NIST 800-53, PCI-DSS, SOC 2, and ISO 27001 mappings would each
  need their own mapping table following the same pattern as
  `app/compliance/cis_aws.py` / `cis_azure.py`.

## Assumptions made

- Assumed a single AWS account and a single Azure subscription per scan
  (no AWS Organizations / multi-account or multi-subscription
  aggregation). A real CSPM product would typically scan across an
  Organization / management group via a delegated administrator account
  and cross-account roles.
- Assumed synchronous, on-demand scanning is the primary usage pattern
  (dashboard button, CLI invocation, or an external cron/CI trigger
  calling the API) rather than continuous/event-driven scanning
  (e.g. reacting to CloudTrail events in near-real-time).
- Assumed the reader/operator has basic AWS/Azure and Python familiarity
  for the installation steps; IAM policy JSON and `az role assignment`
  commands are provided but not a click-by-click console walkthrough.
- Assumed SQLite is acceptable for the target audience (individual
  engineer, small team, portfolio demonstration) rather than designing for
  massive finding volumes from day one.

## What a v2 would add, roughly in priority order

1. **Authentication** — wire up the existing JWT config into real
   session/API-key auth, plus basic RBAC (viewer vs. admin who can change
   finding status).
2. **More scanners** — Lambda (public function URLs, overly permissive
   execution roles), KMS (key policy analysis), VPC (flow logs enabled,
   default VPC usage), Secrets Manager (rotation status).
3. **Multi-account / AWS Organizations support** — cross-account role
   assumption, aggregated dashboard across accounts.
4. **Scheduled scanning** — a proper task queue (Celery/RQ + Redis)
   instead of FastAPI `BackgroundTasks`, plus a scheduler for
   "scan every account nightly."
5. **Finding re-opening logic** and a full audit trail of who changed a
   finding's status and when.
6. **Additional compliance frameworks** (NIST 800-53, PCI-DSS, SOC 2).
7. **Alerting/integrations** — Slack/email notification on new critical
   findings, a webhook system, ticketing system integration (Jira).
8. **CI security scanning of CloudGuard itself** — `pip-audit` /
   `bandit` in CI, dependency update automation.
9. **GCP** — GCP scanner modules following the same `BaseScanner`
   pattern (Azure is done; see the provider model in
   `docs/ARCHITECTURE.md`).

None of this is required for the tool to be useful today — it's included
here because knowing what was deliberately left out (and why) is part of
representing this as real engineering work rather than a finished,
unexamined product.
