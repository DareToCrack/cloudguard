"""Self-contained HTML executive/technical report generator.

Produces a single-file HTML report (inline CSS, no external dependencies)
suitable for emailing, printing to PDF via a browser, or archiving as
point-in-time audit evidence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape

from app.core.orchestrator import ScanReport

# Shared light palette (same as the dashboard): softened but distinct.
SEVERITY_COLORS = {
    "critical": "#b91c1c",
    "high": "#b45309",
    "medium": "#d9a441",
    "low": "#2563eb",
    "info": "#667085",
}

GRADE_COLORS = {"A": "#15803d", "B": "#4d7c0f", "C": "#d9a441", "D": "#b45309", "F": "#b91c1c"}


def _severity_text_color(severity: str) -> str:
    # Medium's amber is too light for white text.
    return "#22262b" if severity == "medium" else "#ffffff"


def _severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#667085")
    return (
        f'<span style="background:{color};color:{_severity_text_color(severity)};'
        f'padding:2px 10px;border-radius:12px;'
        f'font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.03em;">'
        f'{escape(severity)}</span>'
    )


def generate_html_report(report: ScanReport, account_label: str = "Demo Account") -> str:
    risk = report.risk
    grade_color = GRADE_COLORS.get(risk.grade, "#6b7280") if risk else "#6b7280"
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    findings_sorted = sorted(report.findings, key=lambda f: -f.severity.weight)

    rows = []
    for f in findings_sorted:
        compliance_str = ", ".join(
            f"{c.framework.split(' ')[0]} {c.control_id}" for c in f.compliance
        ) or "—"
        rows.append(f"""
        <tr>
          <td>{_severity_badge(f.severity.value)}</td>
          <td><strong>{escape(f.title)}</strong><br>
              <span style="color:#667085;font-size:13px;">{escape(f.description)}</span></td>
          <td style="font-size:12px;">{escape(f.provider.value.upper())}</td>
          <td style="font-family:monospace;font-size:12px;">{escape(f.resource_name)}<br>
              <span style="color:#9ca3af;">{escape(f.region)}</span></td>
          <td style="font-size:13px;">{escape(f.remediation)}</td>
          <td style="font-size:12px;color:#667085;">{escape(compliance_str)}</td>
        </tr>""")

    provider_rows = "".join(
        f"""<tr><td>{escape(provider.upper())}</td><td>{score}</td>
            <td><div style="background:#e5e7eb;border-radius:4px;overflow:hidden;width:150px;">
            <div style="background:{'#15803d' if score>=80 else '#d9a441' if score>=60 else '#b91c1c'};
            width:{score}%;height:8px;"></div></div></td></tr>"""
        for provider, score in sorted((risk.provider_scores or {}).items() if risk else [])
    )

    service_rows = "".join(
        f"""<tr><td>{escape(svc)}</td><td>{score}</td>
            <td><div style="background:#e5e7eb;border-radius:4px;overflow:hidden;width:150px;">
            <div style="background:{'#15803d' if score>=80 else '#d9a441' if score>=60 else '#b91c1c'};
            width:{score}%;height:8px;"></div></div></td></tr>"""
        for svc, score in (risk.service_scores.items() if risk else [])
    )

    severity_summary = "".join(
        f"""<div style="text-align:center;padding:16px;background:#f9fafb;border-radius:8px;flex:1;">
            <div style="font-size:28px;font-weight:700;color:{SEVERITY_COLORS[sev]};">{count}</div>
            <div style="font-size:12px;text-transform:uppercase;color:#6b7280;letter-spacing:.05em;">{sev}</div>
        </div>"""
        for sev, count in (risk.severity_counts if risk else {}).items()
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CloudGuard Security Assessment Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          margin: 0; padding: 40px; color: #111827; background: #ffffff; line-height: 1.5; }}
  .header {{ display:flex; justify-content:space-between; align-items:flex-start;
             border-bottom: 3px solid #1e293b; padding-bottom: 20px; margin-bottom: 30px; }}
  .logo {{ font-size: 24px; font-weight: 800; color: #1e293b; }}
  .logo span {{ color: #2563eb; }}
  .meta {{ text-align:right; font-size: 13px; color: #6b7280; }}
  .score-card {{ display:flex; gap: 20px; align-items:center; background:#f9fafb;
                 border-radius:12px; padding:24px; margin-bottom:30px; }}
  .grade-circle {{ width:90px;height:90px;border-radius:50%;display:flex;align-items:center;
                    justify-content:center;font-size:36px;font-weight:800;color:#fff;
                    background:{grade_color}; flex-shrink:0; }}
  .score-details h2 {{ margin:0 0 4px 0; font-size:20px;}}
  .score-details p {{ margin:0; color:#6b7280; font-size:14px;}}
  .severity-strip {{ display:flex; gap:12px; margin-bottom:30px; }}
  table {{ width:100%; border-collapse:collapse; margin-bottom: 30px;}}
  th {{ text-align:left; font-size:12px; text-transform:uppercase; letter-spacing:.05em;
        color:#6b7280; padding:10px 12px; border-bottom:2px solid #e5e7eb; }}
  td {{ padding:12px; border-bottom:1px solid #f3f4f6; vertical-align:top; font-size:14px; }}
  h2.section {{ font-size:16px; text-transform:uppercase; letter-spacing:.05em; color:#374151;
                border-left: 4px solid #2563eb; padding-left:10px; margin: 36px 0 16px 0; }}
  .footer {{ margin-top:40px; padding-top:20px; border-top:1px solid #e5e7eb;
             font-size:12px; color:#9ca3af; }}
  @media print {{ body {{ padding: 15px; }} }}
</style>
</head>
<body>
  <div class="header">
    <div class="logo">Cloud<span>Guard</span></div>
    <div class="meta">
      Cloud Security Assessment Report<br>
      Account: {escape(account_label)}<br>
      Scan ID: {escape(report.scan_id)}<br>
      Generated: {generated_at} &middot; Mode: {report.mode}
    </div>
  </div>

  <div class="score-card">
    <div class="grade-circle">{risk.grade if risk else "-"}</div>
    <div class="score-details">
      <h2>Security Posture Score: {risk.score if risk else "-"}/100</h2>
      <p>{risk.total_findings if risk else 0} open findings across {len(risk.service_scores) if risk else 0} resource categories &middot; scan completed in {report.duration_seconds:.2f}s</p>
    </div>
  </div>

  <div class="severity-strip">
    {severity_summary}
  </div>

  <h2 class="section">Score by Provider</h2>
  <table>
    <tr><th>Provider</th><th>Score</th><th></th></tr>
    {provider_rows}
  </table>

  <h2 class="section">Score by Resource Category</h2>
  <table>
    <tr><th>Category</th><th>Score</th><th></th></tr>
    {service_rows}
  </table>

  <h2 class="section">Detailed Findings ({len(findings_sorted)})</h2>
  <table>
    <tr><th>Severity</th><th>Finding</th><th>Provider</th><th>Resource</th><th>Remediation</th><th>Compliance</th></tr>
    {''.join(rows)}
  </table>

  <div class="footer">
    Generated by CloudGuard — Cloud Security Posture Management.
    This report reflects the state of scanned resources at the time of the scan and should be
    re-run periodically. Findings marked "resolved" or "risk accepted" in a prior review are
    excluded from this listing.
  </div>
</body>
</html>"""
