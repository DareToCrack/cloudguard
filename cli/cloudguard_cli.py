#!/usr/bin/env python3
"""CloudGuard CLI - run scans and generate reports without the API/dashboard.

Usage:
    python cloudguard_cli.py scan [--region us-east-1] [--profile myprofile]
    python cloudguard_cli.py scan --provider azure
    python cloudguard_cli.py scan --output report.html --format html
    python cloudguard_cli.py scan --output report.json --format json
    python cloudguard_cli.py list-checks
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path

# Allow running this script directly from the cli/ directory.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.core.orchestrator import SCANNER_REGISTRY, ScanOrchestrator  # noqa: E402
from app.reporting.html_report import generate_html_report  # noqa: E402

SEVERITY_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def _print_console_summary(report) -> None:
    risk = report.risk
    print("\n" + "=" * 64)
    print(f"  CloudGuard Scan Report — {report.mode.upper()} MODE")
    print("=" * 64)
    print(f"  Scan ID:   {report.scan_id}")
    print(f"  Duration:  {report.duration_seconds:.2f}s")
    print(f"  Providers: {', '.join(report.providers)}")
    print(f"  Score:     {risk.score}/100  (Grade {risk.grade})")
    for provider, score in sorted((risk.provider_scores or {}).items()):
        print(f"    {provider.upper():<8} {score}/100")
    print(f"  Findings:  {risk.total_findings}")
    print("-" * 64)
    for sev, count in risk.severity_counts.items():
        if count:
            print(f"  {SEVERITY_ICON.get(sev, '•')} {sev.upper():<10} {count}")
    print("-" * 64)

    findings_sorted = sorted(report.findings, key=lambda f: -f.severity.weight)
    for f in findings_sorted[:15]:
        print(f"  [{f.severity.value.upper():<8}] {f.title}")
        print(f"             resource: {f.resource_name} ({f.region})")
    if len(findings_sorted) > 15:
        print(f"  ... and {len(findings_sorted) - 15} more findings (use --output to see all)")
    if report.scanner_errors:
        print("-" * 64)
        print("  Scanner errors:")
        for name, err in report.scanner_errors.items():
            print(f"    {name}: {err}")
    print("=" * 64 + "\n")


def cmd_scan(args: argparse.Namespace) -> None:
    orchestrator = ScanOrchestrator(
        profile=args.profile, region=args.region, provider=args.provider,
        azure_subscription_id=args.azure_subscription_id,
    )
    scan_id = str(uuid.uuid4())
    report = orchestrator.run_full_scan(scan_id)

    _print_console_summary(report)

    if args.output:
        out_path = Path(args.output)
        if args.format == "html":
            out_path.write_text(generate_html_report(report), encoding="utf-8")
        else:
            out_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        print(f"Report written to: {out_path.resolve()}")


def cmd_list_checks(_: argparse.Namespace) -> None:
    print("\nRegistered CloudGuard scanners:\n")
    for scanner_cls in SCANNER_REGISTRY:
        print(
            f"  - {scanner_cls.name}  "
            f"(provider: {getattr(scanner_cls, 'provider', 'aws')}, "
            f"service: {scanner_cls.service})"
        )
    print()


def main() -> None:
    parser = argparse.ArgumentParser(prog="cloudguard", description="CloudGuard CSPM CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Run a full scan against a cloud account (or demo data)")
    scan_p.add_argument("--region", default="us-east-1", help="AWS region to scan")
    scan_p.add_argument("--profile", default=None, help="AWS named profile to use")
    scan_p.add_argument(
        "--provider", choices=["all", "aws", "azure"], default="all",
        help="Cloud provider(s) to scan (default: all)",
    )
    scan_p.add_argument(
        "--azure-subscription-id", default=None,
        help="Azure subscription ID to scan (default: first visible subscription)",
    )
    scan_p.add_argument("--output", default=None, help="Write a report to this file path")
    scan_p.add_argument("--format", choices=["html", "json"], default="json", help="Report format")
    scan_p.set_defaults(func=cmd_scan)

    list_p = sub.add_parser("list-checks", help="List all registered scanner modules")
    list_p.set_defaults(func=cmd_list_checks)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
