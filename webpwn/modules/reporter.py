"""
Module 9 — HTML Report Generator
Fixes applied:
  #4  — Next Steps excludes INFO findings
  #7  — Technologies cleaned (no emails, IPs, HTTP noise)
  #8  — Security Headers block populated from session.header_data
  #9  — WHOIS block populated from session.whois_data
  #10 — Engagement fields show placeholder hints
  #11 — Subdomains populated from session findings
"""
import os
import re
import datetime
from rich.panel import Panel
from rich.console import Console
from modules.session import Session

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

BADGE_COLORS = {
    "CRITICAL": "background:#7f0000;color:#ff8080",
    "HIGH":     "background:#7a3800;color:#ffb347",
    "MEDIUM":   "background:#4a3d00;color:#ffe066",
    "LOW":      "background:#003d33;color:#80cbc4",
    "INFO":     "background:#1a1a2e;color:#9fa8da",
}

SEV_CSS = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff9800",
    "MEDIUM":   "#ffeb3b",
    "LOW":      "#4caf50",
    "INFO":     "#90caf9",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WebPwn Tools — Pentest Report — {target}</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       background: #0d1117; color: #e6edf3; line-height: 1.6; font-size: 14px; }}
.report-header {{ background: #161b22; border-bottom: 2px solid #1f6feb;
                 padding: 2.5rem 3rem 2rem; }}
.report-header h1 {{ font-size: 1.6rem; color: #58a6ff; margin-bottom: 0.4rem; }}
.report-header .meta {{ color: #8b949e; font-size: 0.85rem; font-family: monospace; }}
.confidential-badge {{ display:inline-block; background:#3d0000; color:#ff6b6b;
                      font-size:0.7rem; font-weight:700; padding:2px 10px;
                      border-radius:3px; letter-spacing:.1em; margin-top:0.5rem; }}
.section {{ padding: 2rem 3rem; border-bottom: 1px solid #21262d; }}
.section:last-child {{ border-bottom: none; }}
.section-title {{ font-size: 0.75rem; font-weight: 700; color: #58a6ff;
                 text-transform: uppercase; letter-spacing: .12em;
                 margin-bottom: 1.2rem; display:flex; align-items:center; gap:8px; }}
.section-title::after {{ content:''; flex:1; height:1px; background:#21262d; }}
.eng-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }}
.eng-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
            padding: 0.9rem 1.1rem; }}
.eng-label {{ font-size: 0.7rem; color: #58a6ff; text-transform: uppercase;
             letter-spacing:.08em; margin-bottom:3px; }}
.eng-value {{ font-size: 0.9rem; color: #e6edf3; }}
.eng-hint {{ font-size: 0.75rem; color: #444d56; font-style: italic; }}
.summary-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; }}
.stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
             padding: 1rem; text-align: center; }}
.stat-card .num {{ font-size: 2.2rem; font-weight: 700; }}
.stat-card .lbl {{ font-size: 0.7rem; color: #8b949e; text-transform: uppercase;
                  letter-spacing: .08em; margin-top: 4px; }}
.c-critical{{color:#ff4444}} .c-high{{color:#ff9800}}
.c-medium{{color:#ffeb3b}}   .c-low{{color:#4caf50}} .c-info{{color:#90caf9}}
.profile-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }}
.profile-block {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
                 padding: 1rem 1.2rem; }}
.profile-block h3 {{ font-size: 0.75rem; color: #58a6ff; text-transform: uppercase;
                    letter-spacing:.08em; margin-bottom: 0.6rem;
                    padding-bottom:0.4rem; border-bottom:1px solid #21262d; }}
.profile-row {{ display:flex; gap:0.5rem; padding:3px 0;
               border-bottom:1px solid #161b22; font-size:0.85rem; }}
.profile-key {{ color: #8b949e; width: 130px; flex-shrink:0; }}
.profile-val {{ color: #e6edf3; word-break:break-all; }}
.pill {{ display:inline-block; background:#1c2128; border:1px solid #30363d;
        border-radius:10px; font-size:0.75rem; padding:1px 8px; margin:2px 2px 0 0;
        color:#8b949e; }}
.pill.live {{ background:#0f2010; border-color:#3fb950; color:#3fb950; }}
.subdomain-list {{ max-height:180px; overflow-y:auto; }}
.hdr-present {{ color:#3fb950; font-size:0.78rem; }}
.hdr-missing {{ color:#ff4444; font-size:0.78rem; }}
.risk-table {{ width:100%; border-collapse:collapse; font-size:0.85rem; }}
.risk-table th {{ background:#161b22; color:#8b949e; font-size:0.7rem;
                 text-transform:uppercase; letter-spacing:.08em;
                 padding:0.5rem 0.8rem; text-align:left; border:1px solid #21262d; }}
.risk-table td {{ padding:0.6rem 0.8rem; border:1px solid #21262d; vertical-align:top; }}
.finding {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
           margin-bottom: 1rem; overflow: hidden; }}
.finding-header {{ display: flex; align-items: center; gap: 1rem;
                  padding: 0.7rem 1rem; border-bottom: 1px solid #21262d; }}
.badge {{ font-size: 0.65rem; font-weight: 700; padding: 3px 10px;
         border-radius: 20px; text-transform: uppercase; letter-spacing: .06em;
         flex-shrink:0; }}
.finding-title {{ font-weight: 500; font-size: 0.9rem; }}
.finding-module {{ margin-left: auto; font-size: 0.72rem; color: #8b949e;
                  font-family: monospace; white-space:nowrap; }}
.finding-body {{ padding: 1rem; }}
.finding-body p {{ font-size: 0.85rem; color: #8b949e; margin-bottom: 0.4rem; }}
.field-label {{ font-size: 0.7rem; color: #58a6ff; text-transform: uppercase;
               letter-spacing:.06em; margin-top:0.7rem; margin-bottom:0.25rem; }}
.evidence {{ background: #0d1117; border: 1px solid #21262d; border-radius: 4px;
            padding: 0.5rem 0.75rem; font-family: monospace; font-size: 0.8rem;
            color: #cdd9e5; word-break: break-all; }}
.timestamp {{ font-size:0.72rem; color:#444d56; margin-top:0.5rem; }}
.method-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:1rem; }}
.method-card {{ background:#161b22; border:1px solid #30363d; border-radius:8px;
               padding:0.9rem 1rem; }}
.method-card .phase {{ font-size:0.7rem; color:#3fb950; font-family:monospace;
                      letter-spacing:.06em; margin-bottom:4px; }}
.method-card .mname {{ font-size:0.88rem; font-weight:500; color:#e6edf3; }}
.method-card .mdesc {{ font-size:0.78rem; color:#8b949e; margin-top:3px; }}
.next-step {{ display:flex; gap:0.75rem; align-items:flex-start;
             padding:0.6rem 0; border-bottom:1px solid #21262d; }}
.next-step:last-child {{ border-bottom:none; }}
.step-num {{ background:#1f6feb; color:#fff; font-size:0.7rem; font-weight:700;
            width:20px; height:20px; border-radius:50%; display:flex;
            align-items:center; justify-content:center; flex-shrink:0; margin-top:2px; }}
.step-text {{ font-size:0.85rem; color:#e6edf3; }}
.step-sev {{ font-size:0.72rem; color:#8b949e; }}
.cmd-entry {{ background:#0d1117; border:1px solid #21262d; border-radius:4px;
             padding:0.5rem 0.9rem; margin-bottom:0.4rem;
             font-family:monospace; font-size:0.78rem; color:#8b949e; }}
.cmd-ts {{ color:#3fb950; margin-right:0.75rem; }}
.disclaimer {{ background:#161b22; border-top:2px solid #21262d;
              padding:1.5rem 3rem; font-size:0.78rem; color:#6e7681; }}
.disclaimer strong {{ color:#8b949e; }}
</style>
</head>
<body>
<div class="report-header">
  <h1>Web Application Penetration Test Report</h1>
  <div class="meta">
    Target: <strong>{target}</strong> &nbsp;|&nbsp;
    CMS: {cms} &nbsp;|&nbsp;
    Client: {client} &nbsp;|&nbsp;
    Generated: {timestamp}
  </div>
  <div class="confidential-badge">⚠ CONFIDENTIAL — AUTHORISED PERSONNEL ONLY</div>
</div>

<div class="section">
  <div class="section-title">Engagement Information</div>
  <div class="eng-grid">
    {engagement_html}
  </div>
</div>

<div class="section">
  <div class="section-title">Finding Summary</div>
  <div class="summary-grid">
    <div class="stat-card"><div class="num c-critical">{cnt_critical}</div><div class="lbl">Critical</div></div>
    <div class="stat-card"><div class="num c-high">{cnt_high}</div><div class="lbl">High</div></div>
    <div class="stat-card"><div class="num c-medium">{cnt_medium}</div><div class="lbl">Medium</div></div>
    <div class="stat-card"><div class="num c-low">{cnt_low}</div><div class="lbl">Low</div></div>
    <div class="stat-card"><div class="num c-info">{cnt_info}</div><div class="lbl">Info</div></div>
  </div>
</div>

<div class="section">
  <div class="section-title">Executive Summary</div>
  {executive_summary_html}
</div>

<div class="section">
  <div class="section-title">Target Profile</div>
  <div class="profile-grid">
    {target_profile_html}
  </div>
</div>

<div class="section">
  <div class="section-title">Risk Rating Definitions</div>
  <table class="risk-table">
    <tr><th>Severity</th><th>Business Impact &amp; Remediation Timeframe</th></tr>
    <tr><td><span style="color:#ff4444;font-weight:700">CRITICAL</span></td>
        <td style="color:#8b949e">Remote code execution, full system compromise, credential exposure at scale. Immediate remediation required before next deployment.</td></tr>
    <tr><td><span style="color:#ff9800;font-weight:700">HIGH</span></td>
        <td style="color:#8b949e">Significant impact on confidentiality, integrity or availability. Remediate within 7 days.</td></tr>
    <tr><td><span style="color:#ffeb3b;font-weight:700">MEDIUM</span></td>
        <td style="color:#8b949e">Limited impact or requiring additional conditions to exploit. Remediate within 30 days.</td></tr>
    <tr><td><span style="color:#4caf50;font-weight:700">LOW</span></td>
        <td style="color:#8b949e">Minimal impact, defence-in-depth improvements. Remediate within 90 days.</td></tr>
    <tr><td><span style="color:#90caf9;font-weight:700">INFO</span></td>
        <td style="color:#8b949e">Informational findings, configuration notes. No direct security risk; review at next opportunity.</td></tr>
  </table>
</div>

<div class="section">
  <div class="section-title">Testing Methodology</div>
  <p style="font-size:0.85rem;color:#8b949e;margin-bottom:1rem">
    Testing followed the <strong style="color:#e6edf3">OWASP Testing Guide v4.2</strong> and
    <strong style="color:#e6edf3">PTES (Penetration Testing Execution Standard)</strong> framework.
    All active testing was performed with written authorisation only.
  </p>
  <div class="method-grid">
    <div class="method-card"><div class="phase">P1</div><div class="mname">Recon &amp; Fingerprint</div><div class="mdesc">WHOIS, DNS, HTTP headers, WhatWeb, subdomain enumeration</div></div>
    <div class="method-card"><div class="phase">P2</div><div class="mname">Headers &amp; TLS</div><div class="mdesc">Security header audit, cookie flags, SSL/TLS configuration</div></div>
    <div class="method-card"><div class="phase">P3</div><div class="mname">Dir &amp; File Enum</div><div class="mdesc">Hidden path discovery, backup files, directory listing checks</div></div>
    <div class="method-card"><div class="phase">P4</div><div class="mname">Injection Testing</div><div class="mdesc">XSS (dalfox), SQLi (sqlmap), SSTI, open redirect, CSRF</div></div>
    <div class="method-card"><div class="phase">P5</div><div class="mname">Auth Testing</div><div class="mdesc">Login page discovery, error disclosure, rate limiting, brute-force</div></div>
    <div class="method-card"><div class="phase">P6</div><div class="mname">API &amp; JS Recon</div><div class="mdesc">JavaScript secret scanning, API endpoint discovery</div></div>
    <div class="method-card"><div class="phase">P7</div><div class="mname">CMS-Specific</div><div class="mdesc">WPScan / JoomScan / Droopescan based on detected CMS</div></div>
  </div>
</div>

<div class="section">
  <div class="section-title">Findings</div>
  {findings_html}
</div>

<div class="section">
  <div class="section-title">Conclusion &amp; Recommended Next Steps</div>
  <p style="font-size:0.85rem;color:#8b949e;margin-bottom:1rem">
    The following remediation actions are recommended in priority order.
    Items should be verified via re-testing after fixes are applied.
  </p>
  {next_steps_html}
</div>

<div class="section">
  <div class="section-title">Command Log</div>
  {cmdlog_html}
</div>

<div class="disclaimer">
  <strong>Disclaimer</strong><br><br>
  This report was prepared by <strong>{assessor}</strong> and is intended solely for the named client
  organisation. The findings reflect the security posture of the target system at the time of
  testing ({timestamp}) and may not represent its complete or future security state.<br><br>
  This document is <strong>confidential</strong>. Distribution to parties outside the named
  engagement is prohibited without written consent.<br><br>
  All testing was conducted with explicit written authorisation. Unauthorised use of the
  techniques described herein against systems without permission is illegal.
  <br><br>
  <strong>Generated by WebPwn Tools v2.0</strong> &nbsp;|&nbsp; {timestamp}
</div>
</body>
</html>
"""


def generate_report(session: Session, console: Console):
    console.clear()
    console.print(Panel("[bold]Generate Report[/bold]", border_style="bright_blue"))
    console.print()

    if not session.findings:
        console.print("  [yellow]  No findings to report. Run some modules first.[/yellow]")
        console.print("\n[dim]Press Enter to return...[/dim]")
        input()
        return

    ts  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fname = f"webpwn_report_{session.session_id}.html"
    fpath = os.path.join(session.report_dir, fname)
    counts = session.summary()

    sorted_findings = sorted(session.findings,
                             key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))

    html = HTML_TEMPLATE.format(
        target=_esc(session.target),
        cms=_esc(session.cms or "Unknown"),
        client=_esc(session.client or "—"),
        assessor=_esc(session.assessor or "WebPwn Tools"),
        timestamp=ts,
        cnt_critical=counts.get("CRITICAL", 0),
        cnt_high=counts.get("HIGH", 0),
        cnt_medium=counts.get("MEDIUM", 0),
        cnt_low=counts.get("LOW", 0),
        cnt_info=counts.get("INFO", 0),
        engagement_html=_build_engagement(session),
        executive_summary_html=_build_executive_summary(session, counts),
        target_profile_html=_build_target_profile(session),
        findings_html=_build_findings(sorted_findings),
        next_steps_html=_build_next_steps(sorted_findings),   # Fix #4
        cmdlog_html=_build_cmdlog(session),
    )

    os.makedirs(session.report_dir, exist_ok=True)
    with open(fpath, "w", encoding="utf-8") as out:
        out.write(html)

    console.print(f"  [bright_green]✓ Report saved:[/bright_green] [cyan]{fpath}[/cyan]")
    console.print()
    for sev, cnt in counts.items():
        if cnt:
            clr = {"CRITICAL":"bold red","HIGH":"yellow","MEDIUM":"yellow",
                   "LOW":"cyan","INFO":"dim"}.get(sev, "white")
            console.print(f"    [{clr}]{sev}: {cnt}[/{clr}]")

    console.print(f"\n  [dim]Open in browser: firefox {fpath}[/dim]")
    console.print("\n[dim]Press Enter to return to menu...[/dim]")
    input()


# ── Section builders ──────────────────────────────────────────────

def _build_engagement(session: Session) -> str:
    """Fix #10: Show placeholder hints for empty fields."""
    def _eng_card(label, value, hint=""):
        display = _esc(value) if value else f'<span class="eng-hint">{hint}</span>'
        return f'<div class="eng-card"><div class="eng-label">{label}</div><div class="eng-value">{display}</div></div>'

    return (
        _eng_card("Assessor / Tester",       session.assessor,   "e.g. Jane Smith") +
        _eng_card("Client / Organisation",   session.client,     "e.g. Acme Corp") +
        _eng_card("Test Start Date",         session.test_start, "e.g. 2026-07-01") +
        _eng_card("Test End Date",           session.test_end,   "e.g. 2026-07-07") +
        _eng_card("Authorisation Reference", session.auth_ref,   "e.g. Email from CEO dated 2026-06-30") +
        _eng_card("In-Scope",               session.in_scope,   "e.g. https://target.com and all subpages") +
        _eng_card("Out-of-Scope",           session.out_scope,  "e.g. Payment gateway, third-party APIs") +
        _eng_card("Testing Type",           session.test_type,  "")
    )


def _build_executive_summary(session: Session, counts: dict) -> str:
    total = len(session.findings)
    overall = "CRITICAL" if counts["CRITICAL"] else \
              "HIGH" if counts["HIGH"] else \
              "MEDIUM" if counts["MEDIUM"] else "LOW"
    color = SEV_CSS.get(overall, "#e6edf3")
    high_crit = counts["CRITICAL"] + counts["HIGH"]

    summary = f"""
    <p style="margin-bottom:0.8rem;font-size:0.9rem;color:#8b949e">
      An authorised web application penetration test was conducted against
      <strong style="color:#e6edf3">{_esc(session.target)}</strong>.
      The assessment identified a total of <strong style="color:#e6edf3">{total}</strong> finding(s),
      with an overall risk rating of <span style='color:{color};font-weight:700'>{overall}</span>.
    </p>"""

    if counts["CRITICAL"]:
        summary += '<p style="margin-bottom:0.8rem;font-size:0.9rem;color:#8b949e">One or more critical vulnerabilities were identified that require immediate remediation.</p>'
    if high_crit:
        summary += f'<p style="font-size:0.9rem;color:#8b949e"><strong style="color:#ff9800">{high_crit} high or critical issue(s)</strong> require priority attention before the next production deployment.</p>'

    return summary


def _build_target_profile(session: Session) -> str:
    """Fix #7 #8 #9 #11: Clean tech, populate headers/WHOIS/subdomains from session."""
    from urllib.parse import urlparse
    domain = urlparse(session.target).netloc or session.target

    # IP from findings
    ip = "—"
    for f in session.findings:
        if f["module"] == "Recon" and "IP Address" in f["title"]:
            ip = f["evidence"]
            break

    # CDN / server from tech_data
    server = "—"
    cdn    = "—"
    tech_pills = ""
    if session.tech_data:
        # Fix #7: filter out noise — emails, IPs, HTTP codes, header names
        noise_patterns = [
            r'^\d{3}\s',           # HTTP status codes
            r'@',                  # emails
            r'^\d{1,3}\.\d{1,3}', # IPs
            r'^[a-z]+-[a-z]+-[a-z]',  # header names like x-content-type
            r'max-age=',           # cache directives
            r'application/',       # mime types
        ]
        clean_techs = []
        for t in session.tech_data:
            t = t.strip()
            if not t or len(t) > 60:
                continue
            if any(re.search(p, t, re.IGNORECASE) for p in noise_patterns):
                continue
            clean_techs.append(t)

        tech_pills = " ".join(f'<span class="pill">{_esc(t)}</span>' for t in clean_techs[:15])

    # Fix #8: Security headers from session.header_data
    present_hdrs = session.header_data.get("present", [])
    missing_hdrs = session.header_data.get("missing", [])
    hdr_present_html = "".join(f'<div class="hdr-present">✓ {_esc(h)}</div>' for h in present_hdrs) or '<span style="color:#444">—</span>'
    hdr_missing_html = "".join(f'<div class="hdr-missing">✗ {_esc(h)}</div>' for h in missing_hdrs) or '<span style="color:#444">—</span>'

    # Fix #9: WHOIS from session.whois_data
    def _whois_row(label, key):
        val = session.whois_data.get(key, "")
        display = _esc(val) if val else '<span style="color:#444">—</span>'
        return f'<div class="profile-row"><span class="profile-key">{label}</span><span class="profile-val">{display}</span></div>'

    # Fix #11: Subdomains from findings
    subdomains = [f["evidence"] for f in session.findings
                  if f["module"] == "Subdomain Enum" and f["evidence"]]
    if not subdomains:
        subdomains = [domain]
    subdomain_pills = "".join(
        f'<span class="pill live">{_esc(s)}</span>' for s in subdomains[:30]
    )

    # DNS from session
    dns_mx  = _esc(", ".join(session.whois_data.get("mx", [])))  or '<span style="color:#444">—</span>'
    dns_ns  = _esc(", ".join(session.whois_data.get("ns", [])))  or '<span style="color:#444">—</span>'
    dns_txt = _esc(", ".join(session.whois_data.get("txt", []))) or '<span style="color:#444">—</span>'

    return f"""
    <div class="profile-block">
      <h3>Identity</h3>
      <div class="profile-row"><span class="profile-key">Domain</span><span class="profile-val">{_esc(domain)}</span></div>
      <div class="profile-row"><span class="profile-key">IP Address(es)</span><span class="profile-val">{_esc(ip)}</span></div>
      <div class="profile-row"><span class="profile-key">CMS / Platform</span><span class="profile-val">{_esc(session.cms or "Unknown")}</span></div>
      <div class="profile-row"><span class="profile-key">Server</span><span class="profile-val">{_esc(server)}</span></div>
      <div class="profile-row"><span class="profile-key">CDN</span><span class="profile-val">{_esc(cdn)}</span></div>
    </div>
    <div class="profile-block">
      <h3>Subdomains ({len(subdomains)} found)</h3>
      <div class="subdomain-list">{subdomain_pills}</div>
    </div>
    <div class="profile-block">
      <h3>Technologies</h3>
      <div>{tech_pills or '<span style="color:#444">Run Module 1 (Recon) to populate</span>'}</div>
    </div>
    <div class="profile-block">
      <h3>DNS Records</h3>
      <div class="profile-row"><span class="profile-key">MX</span><span class="profile-val">{dns_mx}</span></div>
      <div class="profile-row"><span class="profile-key">NS</span><span class="profile-val">{dns_ns}</span></div>
      <div class="profile-row"><span class="profile-key">TXT</span><span class="profile-val">{dns_txt}</span></div>
    </div>
    <div class="profile-block">
      <h3>WHOIS</h3>
      {_whois_row("Registrar", "Registrar")}
      {_whois_row("Registrant Org", "Registrant Org")}
      {_whois_row("Created", "Creation Date")}
      {_whois_row("Expiry", "Expiry Date")}
    </div>
    <div class="profile-block">
      <h3>Security Headers</h3>
      <div style="margin-bottom:6px">
        <span style="font-size:0.72rem;color:#3fb950">PRESENT</span><br>
        {hdr_present_html}
      </div>
      <div>
        <span style="font-size:0.72rem;color:#ff4444">MISSING</span><br>
        {hdr_missing_html}
      </div>
    </div>"""


def _build_findings(sorted_findings: list) -> str:
    if not sorted_findings:
        return "<p style='color:#8b949e'>No findings logged.</p>"
    html = ""
    for f in sorted_findings:
        sev  = f["severity"]
        bstyle = BADGE_COLORS.get(sev, "")
        evid = f'<div class="field-label">Evidence</div><div class="evidence">{_esc(f["evidence"])}</div>' if f.get("evidence") else ""
        rem  = f'<div class="field-label">Remediation</div><p>{_esc(f["remediation"])}</p>' if f.get("remediation") else ""
        html += f"""
        <div class="finding">
          <div class="finding-header">
            <span class="badge" style="{bstyle}">{sev}</span>
            <span class="finding-title">{_esc(f["title"])}</span>
            <span class="finding-module">{_esc(f.get("module",""))}</span>
          </div>
          <div class="finding-body">
            <p>{_esc(f.get("description",""))}</p>
            {evid}{rem}
            <div class="timestamp">{f.get("timestamp","")}</div>
          </div>
        </div>"""
    return html


def _build_next_steps(sorted_findings: list) -> str:
    """Fix #4: Exclude INFO findings from next steps."""
    actionable = [f for f in sorted_findings if f["severity"] != "INFO"]
    if not actionable:
        return "<p style='color:#8b949e'>No actionable findings.</p>"
    html = ""
    for i, f in enumerate(actionable, 1):
        color = SEV_CSS.get(f["severity"], "#e6edf3")
        html += f"""
        <div class="next-step">
          <div class="step-num">{i}</div>
          <div>
            <div class="step-text">{_esc(f["title"])}</div>
            <div class="step-sev" style="color:{color}">{f["severity"]} — {_esc(f.get("module",""))}</div>
          </div>
        </div>"""
    return html


def _build_cmdlog(session: Session) -> str:
    if not session.command_log:
        return "<p style='color:#8b949e'>No commands logged.</p>"
    return "".join(
        f'<div class="cmd-entry"><span class="cmd-ts">{e["timestamp"][:19]}</span>{_esc(e["cmd"][:200])}</div>'
        for e in session.command_log[-50:]
    )


def _esc(s: str) -> str:
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")
