# Usage

## Dashboard walkthrough

1. **Run a scan.** Pick a provider in the dropdown next to the scan
   button — **All providers**, **AWS**, or **Azure** — then click
   **▶ Run scan**. In demo mode this completes in well under a second;
   against a real account it depends on account size (typically a few
   seconds).
2. **Dashboard tab.** Shows the overall posture gauge (0–100, letter
   grade), a severity breakdown, per-provider scores (AWS vs Azure),
   per-resource-category scores, top-line stats, and a preview of the
   highest-severity findings.
3. **Findings tab.** The full findings table — search by title/resource
   name, filter by severity, provider, or resource type, and change a
   finding's status (`open` / `resolved` / `suppressed` / `risk_accepted`)
   inline. Status changes take effect immediately via the API; they
   persist across future scans (matched by fingerprint).
4. **Compliance tab.** Every CIS control (AWS Foundations Benchmark v3.0
   and Azure Foundations Benchmark v3.0.0) that has at least one open
   finding mapped to it, sorted by highest severity first — useful for an
   "are we ready for an audit" view.
5. **Export report.** Opens a self-contained HTML report for the most
   recent scan in a new tab — print it to PDF, email it, or archive it as
   point-in-time evidence.

The mode pill next to the scan button (`DEMO MODE` / `LIVE MODE` /
`MIXED MODE`) always tells you which data source produced the current
results. `MIXED MODE` means one provider was scanned live and the other
fell back to demo data.

## Azure checks

17 checks across 6 Azure scanner modules, mapped to CIS Microsoft Azure
Foundations Benchmark v3.0.0 controls (see
[`backend/app/compliance/cis_azure.py`](../backend/app/compliance/cis_azure.py)):

| Check | What it flags | Severity | CIS v3.0.0 |
|---|---|---|---|
| `AZ_STORAGE_PUBLIC_BLOB` | Storage account allows anonymous blob access | High | 4.17 |
| `AZ_STORAGE_HTTPS_ONLY` | Secure transfer (HTTPS) not required | Medium | 4.1 |
| `AZ_STORAGE_MIN_TLS` | Minimum TLS version below 1.2 | Medium | 4.15 |
| `AZ_STORAGE_NO_ENCRYPTION` | Infrastructure encryption not enabled | Low | 4.2 |
| `AZ_STORAGE_NETWORK_OPEN` | Default network access rule is Allow | Medium | 4.7 |
| `AZ_NSG_SSH_OPEN_WORLD` | NSG allows SSH (22) from 0.0.0.0/0 | Critical | 7.2 |
| `AZ_NSG_RDP_OPEN_WORLD` | NSG allows RDP (3389) from 0.0.0.0/0 | Critical | 7.1 |
| `AZ_NSG_ANY_PORT_OPEN_WORLD` | NSG allows all ports from 0.0.0.0/0 | High | 7.1, 7.2 |
| `AZ_RBAC_BROAD_OWNER` | Owner role at subscription scope | High | — (see below) |
| `AZ_RBAC_BROAD_CONTRIBUTOR` | Contributor role at subscription scope | Medium | — (see below) |
| `AZ_ROLE_UNUSED_CUSTOM` | Custom role with no assignments | Low | — (see below) |
| `AZ_SQL_PUBLIC_ACCESS` | SQL server public network access enabled | High | 5.1.7 |
| `AZ_SQL_NO_AUDITING` | SQL server auditing not enabled | Medium | 5.1.1 |
| `AZ_SQL_NO_TDE` | Database transparent data encryption disabled | Medium | 5.1.5 |
| `AZ_KV_NO_SOFT_DELETE` | Key Vault soft delete disabled | Medium | 3.3.5 |
| `AZ_KV_NO_PURGE_PROTECTION` | Key Vault purge protection disabled | Medium | 3.3.5 |
| `AZ_DISK_NO_ENCRYPTION` | Managed disk encryption at rest not enabled | Medium | 8.3, 8.4 |

The three RBAC checks have no direct CIS v3.0.0 control (control 2.23
covers custom *administrator* roles, not broad built-in assignments or
unused custom roles), so they carry Microsoft Learn references instead
of a CIS mapping.

## CLI reference

```
python cli/cloudguard_cli.py scan [options]
python cli/cloudguard_cli.py list-checks
```

### `scan`

| Flag | Default | Description |
|---|---|---|
| `--region` | `us-east-1` | AWS region to scan (live mode only; demo mode ignores this) |
| `--profile` | none | Named AWS CLI profile to use |
| `--provider` | `all` | `all`, `aws`, or `azure` |
| `--azure-subscription-id` | none | Azure subscription to scan (default: first visible subscription) |
| `--output` | none | File path to write a report to |
| `--format` | `json` | `html` or `json`, used with `--output` |

Examples:

```bash
# Console summary only, no file output
python cli/cloudguard_cli.py scan

# Azure only
python cli/cloudguard_cli.py scan --provider azure

# Full JSON report for scripting/CI
python cli/cloudguard_cli.py scan --output findings.json --format json

# Printable HTML report against a real account
python cli/cloudguard_cli.py scan --profile prod-readonly --region us-east-1 \
  --output posture-report.html --format html
```

Exit behavior: the CLI always exits 0 on a completed scan (even if
findings were detected) — findings are the expected output of a working
scanner, not a tool failure. Scanner-level errors (e.g. a missing IAM
permission for one service) are printed but do not abort the scan for
other services.

### `list-checks`

Prints every registered scanner module, its provider, and the service it
targets — useful for confirming what CloudGuard will and won't check
before running it against a real account.

## API reference

Full interactive documentation is auto-generated at `/api/docs`
(Swagger UI) and `/api/redoc` whenever the server is running. Key
endpoints:

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/health` | Liveness/health check |
| `POST` | `/api/scans/sync` | Run a scan synchronously, return the result (body: `{"provider": "all" \| "aws" \| "azure"}`) |
| `POST` | `/api/scans` | Start a scan in the background, returns `scan_id` immediately |
| `GET` | `/api/scans` | List past scans |
| `GET` | `/api/scans/{scan_id}` | Get a specific scan's summary (includes `provider_scores`) |
| `GET` | `/api/scans/{scan_id}/findings` | Get all findings from a specific scan |
| `GET` | `/api/findings` | List/filter open findings across all scans (`?severity=`, `?provider=`, `?resource_type=`, `?search=`) |
| `PATCH` | `/api/findings/{finding_id}` | Update a finding's status |
| `GET` | `/api/dashboard` | Aggregated dashboard summary + score trend |
| `GET` | `/api/compliance/summary` | Open findings grouped by compliance control |
| `GET` | `/api/reports/{scan_id}/html` | Self-contained HTML report |
| `GET` | `/api/reports/{scan_id}/json` | Full JSON report |

Example: trigger a scan and fetch its findings with `curl`:

```bash
SCAN=$(curl -s -X POST http://localhost:8000/api/scans/sync \
  -H "Content-Type: application/json" -d '{"region":"us-east-1"}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")

curl -s "http://localhost:8000/api/scans/$SCAN/findings" | python3 -m json.tool
```

## Understanding the risk score

The posture score is 0–100 (higher is better), with a letter grade:

| Score | Grade |
|---|---|
| 90–100 | A |
| 80–89 | B |
| 70–79 | C |
| 60–69 | D |
| 0–59 | F |

The score is driven entirely by **open** findings, weighted by severity
(`critical > high > medium > low > info`), with diminishing returns
applied to large numbers of same-severity findings so that one repeated
low-severity issue across many resources doesn't dominate the score the
way a handful of criticals does. See
[`ARCHITECTURE.md`](ARCHITECTURE.md#risk-scoring-model) for the exact
formula. Marking a finding `resolved`, `suppressed`, or `risk_accepted`
removes it from the score calculation immediately.
