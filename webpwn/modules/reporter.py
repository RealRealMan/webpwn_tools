"""
Module 9 — HTML Report Generator
Produces a full professional pentest report including:
  - Engagement info
  - Executive summary
  - Target profile (domain, subdomains, IP, server, DNS, WHOIS, TLS)
  - Risk rating definitions
  - Methodology
  - Findings (grouped by severity)
  - Conclusion & next steps
  - Command log
  - Disclaimer
"""
import os
import datetime
from rich.panel import Panel
from rich.console import Console
from rich.prompt import Prompt, Confirm
from modules.session import Session

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

BADGE_COLORS = {
    "CRITICAL": "background:#7f0000;color:#ff8080",
    "HIGH":     "background:#7a3800;color:#ffb347",
    "MEDIUM":   "background:#4a3d00;color:#ffe066",
    "LOW":      "background:#003d33;color:#80cbc4",
    "INFO":     "background:#1a1a2e;color:#9fa8da",
}

CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       background: #0d1117; color: #e6edf3; line-height: 1.6; font-size: 14px; }

/* ── Header ── */
.report-header { background: #161b22; border-bottom: 2px solid #1f6feb;
                 padding: 2.5rem 3rem 2rem; }
.report-header h1 { font-size: 1.6rem; color: #58a6ff; margin-bottom: 0.4rem; }
.report-header .meta { color: #8b949e; font-size: 0.85rem; font-family: monospace; }
.confidential-badge { display:inline-block; background:#3d0000; color:#ff6b6b;
                      font-size:0.7rem; font-weight:700; padding:2px 10px;
                      border-radius:3px; letter-spacing:.1em; margin-top:0.5rem; }

/* ── Section wrapper ── */
.section { padding: 2rem 3rem; border-bottom: 1px solid #21262d; }
.section:last-child { border-bottom: none; }
.section-title { font-size: 0.75rem; font-weight: 700; color: #58a6ff;
                 text-transform: uppercase; letter-spacing: .12em;
                 margin-bottom: 1.2rem; display:flex; align-items:center; gap:8px; }
.section-title::after { content:''; flex:1; height:1px; background:#21262d; }

/* ── Engagement table ── */
.eng-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
.eng-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
            padding: 0.9rem 1.1rem; }
.eng-label { font-size: 0.7rem; color: #58a6ff; text-transform: uppercase;
             letter-spacing:.08em; margin-bottom:3px; }
.eng-value { font-size: 0.9rem; color: #e6edf3; }

/* ── Summary cards ── */
.summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; }
.stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
             padding: 1rem; text-align: center; }
.stat-card .num { font-size: 2.2rem; font-weight: 700; }
.stat-card .lbl { font-size: 0.7rem; color: #8b949e; text-transform: uppercase;
                  letter-spacing: .08em; margin-top: 4px; }
.c-critical{color:#ff4444} .c-high{color:#ff9800}
.c-medium{color:#ffeb3b}   .c-low{color:#4caf50} .c-info{color:#90caf9}

/* ── Target profile ── */
.profile-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }
.profile-block { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
                 padding: 1rem 1.2rem; }
.profile-block h3 { font-size: 0.75rem; color: #58a6ff; text-transform: uppercase;
                    letter-spacing:.08em; margin-bottom: 0.6rem;
                    padding-bottom:0.4rem; border-bottom:1px solid #21262d; }
.profile-row { display:flex; gap:0.5rem; padding:3px 0;
               border-bottom:1px solid #161b22; font-size:0.85rem; }
.profile-key { color: #8b949e; width: 130px; flex-shrink:0; }
.profile-val { color: #e6edf3; word-break:break-all; }
.pill { display:inline-block; background:#1c2128; border:1px solid #30363d;
        border-radius:10px; font-size:0.75rem; padding:1px 8px; margin:2px 2px 0 0;
        color:#8b949e; }
.pill.live { background:#0f2010; border-color:#3fb950; color:#3fb950; }
.subdomain-list { max-height:180px; overflow-y:auto; }

/* ── Risk rating table ── */
.risk-table { width:100%; border-collapse:collapse; font-size:0.85rem; }
.risk-table th { background:#161b22; color:#8b949e; font-size:0.7rem;
                 text-transform:uppercase; letter-spacing:.08em;
                 padding:0.5rem 0.8rem; text-align:left; border:1px solid #21262d; }
.risk-table td { padding:0.6rem 0.8rem; border:1px solid #21262d; vertical-align:top; }

/* ── Findings ── */
.finding { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
           margin-bottom: 1rem; overflow: hidden; }
.finding-header { display: flex; align-items: center; gap: 1rem;
                  padding: 0.7rem 1rem; border-bottom: 1px solid #21262d; }
.badge { font-size: 0.65rem; font-weight: 700; padding: 3px 10px;
         border-radius: 20px; text-transform: uppercase; letter-spacing: .06em;
         flex-shrink:0; }
.finding-title { font-weight: 500; font-size: 0.9rem; }
.finding-module { margin-left: auto; font-size: 0.72rem; color: #8b949e;
                  font-family: monospace; white-space:nowrap; }
.finding-body { padding: 1rem; }
.finding-body p { font-size: 0.85rem; color: #8b949e; margin-bottom: 0.4rem; }
.field-label { font-size: 0.7rem; color: #58a6ff; text-transform: uppercase;
               letter-spacing:.06em; margin-top:0.7rem; margin-bottom:0.25rem; }
.evidence { background: #0d1117; border: 1px solid #21262d; border-radius: 4px;
            padding: 0.5rem 0.75rem; font-family: monospace; font-size: 0.8rem;
            color: #cdd9e5; word-break: break-all; }
.timestamp { font-size:0.72rem; color:#444d56; margin-top:0.5rem; }

/* ── Methodology / conclusion ── */
.method-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:1rem; }
.method-card { background:#161b22; border:1px solid #30363d; border-radius:8px;
               padding:0.9rem 1rem; }
.method-card .phase { font-size:0.7rem; color:#3fb950; font-family:monospace;
                      letter-spacing:.06em; margin-bottom:4px; }
.method-card .mname { font-size:0.88rem; font-weight:500; color:#e6edf3; }
.method-card .mdesc { font-size:0.78rem; color:#8b949e; margin-top:3px; }
.next-step { display:flex; gap:0.75rem; align-items:flex-start;
             padding:0.6rem 0; border-bottom:1px solid #21262d; }
.next-step:last-child { border-bottom:none; }
.step-num { background:#1f6feb; color:#fff; font-size:0.7rem; font-weight:700;
            width:20px; height:20px; border-radius:50%; display:flex;
            align-items:center; justify-content:center; flex-shrink:0; margin-top:2px; }
.step-text { font-size:0.85rem; color:#e6edf3; }
.step-sev { font-size:0.72rem; color:#8b949e; }

/* ── Command log ── */
.cmd-entry { background:#0d1117; border:1px solid #21262d; border-radius:4px;
             padding:0.5rem 0.9rem; margin-bottom:0.4rem;
             font-family:monospace; font-size:0.78rem; color:#8b949e; }
.cmd-ts { color:#3fb950; margin-right:0.75rem; }

/* ── Footer / disclaimer ── */
.disclaimer { background:#161b22; border-top:2px solid #21262d;
              padding:1.5rem 3rem; font-size:0.78rem; color:#6e7681; }
.disclaimer strong { color:#8b949e; }
"""


def generate_report(session: Session, console: Console):
    console.clear()
    console.print(Panel("[bold]Generate Report[/bold]", border_style="bright_blue"))
    console.print()

    # Collect engagement info if not already set
    _prompt_engagement(session, console)

    if not session.findings and not session.target:
        console.print("  [yellow]  No data to report. Run some modules first.[/yellow]")
        console.print("\n[dim]Press Enter to return...[/dim]")
        input()
        return

    ts    = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"webpwn_report_{session.session_id}.html"
    fpath = os.path.join(session.report_dir, fname)

    html = _build_html(session)

    os.makedirs(session.report_dir, exist_ok=True)
    with open(fpath, "w", encoding="utf-8") as f:
        f.write(html)

    counts = session.summary()
    console.print(f"  [bright_green]✓ Report saved:[/bright_green] [cyan]{fpath}[/cyan]")
    console.print()
    console.print(f"  Total findings: [yellow]{len(session.findings)}[/yellow]")
    for sev, cnt in counts.items():
        if cnt:
            colors = {"CRITICAL":"bold red","HIGH":"yellow","MEDIUM":"yellow",
                      "LOW":"cyan","INFO":"dim"}
            console.print(f"    [{colors.get(sev,'white')}]{sev}: {cnt}[/{colors.get(sev,'white')}]")

    console.print(f"\n  [dim]Open: firefox {fpath}[/dim]")
    console.print()
    console.print("[dim]Press Enter to return to menu...[/dim]")
    input()


def _prompt_engagement(session: Session, console: Console):
    """Ask for engagement details if not already filled in."""
    eng = session.engagement
    if eng.get("tester_name") and eng.get("client_name"):
        return   # already set

    console.print("  [bold]Engagement details[/bold] [dim](for report cover — press Enter to skip)[/dim]")
    console.print()
    fields = [
        ("tester_name",  "Tester / Assessor name"),
        ("client_name",  "Client / Organisation name"),
        ("date_start",   "Test start date (e.g. 2026-07-01)"),
        ("date_end",     "Test end date"),
        ("auth_ref",     "Authorisation document reference"),
        ("scope",        "In-scope (brief)"),
        ("out_of_scope", "Out-of-scope (brief)"),
    ]
    for key, label in fields:
        val = Prompt.ask(f"  [cyan]{label}[/cyan]",
                         default=eng.get(key, "")).strip()
        eng[key] = val
    session.engagement = eng
    console.print()


# ── HTML builders ──────────────────────────────────────────────────────────

def _build_html(session: Session) -> str:
    now     = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    counts  = session.summary()
    profile = session.target_profile
    eng     = session.engagement

    # Risk level for executive summary
    if counts["CRITICAL"] > 0:
        risk_level = "<span style='color:#ff4444;font-weight:700'>CRITICAL</span>"
        risk_desc  = "One or more critical vulnerabilities were identified that require immediate remediation."
    elif counts["HIGH"] > 0:
        risk_level = "<span style='color:#ff9800;font-weight:700'>HIGH</span>"
        risk_desc  = "High-severity vulnerabilities were found that pose significant risk and should be addressed promptly."
    elif counts["MEDIUM"] > 0:
        risk_level = "<span style='color:#ffeb3b;font-weight:700'>MEDIUM</span>"
        risk_desc  = "Medium-severity issues were identified. These should be addressed as part of regular security maintenance."
    else:
        risk_level = "<span style='color:#4caf50;font-weight:700'>LOW / INFORMATIONAL</span>"
        risk_desc  = "No high-severity issues were found. Informational findings are noted for awareness."

    sections = [
        _section_header(session, eng, now),
        _section_engagement(eng),
        _section_summary(counts),
        _section_executive_summary(risk_level, risk_desc, counts, session),
        _section_target_profile(profile, session),
        _section_risk_ratings(),
        _section_methodology(),
        _section_findings(session),
        _section_conclusion(session),
        _section_cmdlog(session),
        _section_disclaimer(eng, now),
    ]

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WebPwn Tools — Pentest Report — {_esc(session.target)}</title>
<style>{CSS}</style>
</head>
<body>
{''.join(sections)}
</body>
</html>"""


def _section_header(session, eng, now):
    client = _esc(eng.get("client_name", "")) or "—"
    return f"""
<div class="report-header">
  <h1>Web Application Penetration Test Report</h1>
  <div class="meta">
    Target: <strong>{_esc(session.target)}</strong> &nbsp;|&nbsp;
    CMS: {_esc(session.cms or 'Unknown')} &nbsp;|&nbsp;
    Client: {client} &nbsp;|&nbsp;
    Generated: {now}
  </div>
  <div class="confidential-badge">⚠ CONFIDENTIAL — AUTHORISED PERSONNEL ONLY</div>
</div>"""


def _section_engagement(eng):
    def row(label, key):
        val = _esc(eng.get(key, "")) or "<span style='color:#444'>—</span>"
        return f'<div class="eng-card"><div class="eng-label">{label}</div><div class="eng-value">{val}</div></div>'

    return f"""
<div class="section">
  <div class="section-title">Engagement Information</div>
  <div class="eng-grid">
    {row("Assessor / Tester", "tester_name")}
    {row("Client / Organisation", "client_name")}
    {row("Test Start Date", "date_start")}
    {row("Test End Date", "date_end")}
    {row("Authorisation Reference", "auth_ref")}
    {row("In-Scope", "scope")}
    {row("Out-of-Scope", "out_of_scope")}
    <div class="eng-card"><div class="eng-label">Testing Type</div>
      <div class="eng-value">Black-box / Grey-box Web Application Pentest</div></div>
  </div>
</div>"""


def _section_summary(counts):
    return f"""
<div class="section">
  <div class="section-title">Finding Summary</div>
  <div class="summary-grid">
    <div class="stat-card"><div class="num c-critical">{counts['CRITICAL']}</div><div class="lbl">Critical</div></div>
    <div class="stat-card"><div class="num c-high">{counts['HIGH']}</div><div class="lbl">High</div></div>
    <div class="stat-card"><div class="num c-medium">{counts['MEDIUM']}</div><div class="lbl">Medium</div></div>
    <div class="stat-card"><div class="num c-low">{counts['LOW']}</div><div class="lbl">Low</div></div>
    <div class="stat-card"><div class="num c-info">{counts['INFO']}</div><div class="lbl">Info</div></div>
  </div>
</div>"""


def _section_executive_summary(risk_level, risk_desc, counts, session):
    total = sum(counts.values())
    high_plus = counts["CRITICAL"] + counts["HIGH"]
    return f"""
<div class="section">
  <div class="section-title">Executive Summary</div>
  <p style="margin-bottom:0.8rem;font-size:0.9rem;color:#8b949e">
    An authorised web application penetration test was conducted against
    <strong style="color:#e6edf3">{_esc(session.target)}</strong>.
    The assessment identified a total of <strong style="color:#e6edf3">{total}</strong> finding(s),
    with an overall risk rating of {risk_level}.
  </p>
  <p style="margin-bottom:0.8rem;font-size:0.9rem;color:#8b949e">{risk_desc}</p>
  <p style="font-size:0.9rem;color:#8b949e">
    {f'<strong style="color:#ff9800">{high_plus} high or critical issue(s)</strong> require priority attention before the next production deployment.' if high_plus else 'No critical or high-severity issues were identified during this assessment.'}
    The findings and recommended remediations are detailed in the sections below.
  </p>
</div>"""


def _section_target_profile(profile, session):
    def kv(label, val):
        v = _esc(str(val)) if val else "<span style='color:#444'>—</span>"
        return f'<div class="profile-row"><span class="profile-key">{label}</span><span class="profile-val">{v}</span></div>'

    def pills(items, cls=""):
        if not items:
            return "<span style='color:#444'>—</span>"
        return " ".join(f'<span class="pill {cls}">{_esc(i)}</span>' for i in items)

    subdomains_html = ""
    if profile["subdomains"]:
        subdomains_html = f'<div class="subdomain-list">{pills(profile["subdomains"], "live")}</div>'
    else:
        subdomains_html = "<span style='color:#444'>None found / not scanned</span>"

    dns_mx = ", ".join(profile["dns_mx"]) or "—"
    dns_ns = ", ".join(profile["dns_ns"]) or "—"
    dns_txt_short = profile["dns_txt"][:3]

    return f"""
<div class="section">
  <div class="section-title">Target Profile</div>
  <div class="profile-grid">

    <div class="profile-block">
      <h3>Identity</h3>
      {kv("Domain", profile["domain"] or session.target)}
      {kv("IP Address(es)", ", ".join(profile["ip_addresses"]))}
      {kv("CMS / Platform", (profile["cms"] or session.cms or "Unknown"))}
      {kv("CMS Version", profile["cms_version"])}
      {kv("CDN", profile["cdn"])}
      {kv("Hosting / Cloud", profile["hosting"])}
    </div>

    <div class="profile-block">
      <h3>Subdomains</h3>
      {subdomains_html}
    </div>

    <div class="profile-block">
      <h3>Server & Technology</h3>
      {kv("Server", profile["server"])}
      <div class="profile-row">
        <span class="profile-key">Technologies</span>
        <span class="profile-val">{pills(profile["technologies"])}</span>
      </div>
    </div>

    <div class="profile-block">
      <h3>DNS Records</h3>
      {kv("MX", dns_mx)}
      {kv("NS", dns_ns)}
      {"".join(kv("TXT", t) for t in dns_txt_short)}
    </div>

    <div class="profile-block">
      <h3>WHOIS</h3>
      {kv("Registrar", profile["whois_registrar"])}
      {kv("Registrant Org", profile["whois_org"])}
      {kv("Created", profile["whois_created"])}
      {kv("Expiry", profile["whois_expiry"])}
    </div>

    <div class="profile-block">
      <h3>Security Headers</h3>
      <div style="margin-bottom:6px">
        <span style="font-size:0.72rem;color:#3fb950">PRESENT</span><br>
        {pills(profile["headers_present"]) or "<span style='color:#444'>—</span>"}
      </div>
      <div>
        <span style="font-size:0.72rem;color:#ff4444">MISSING</span><br>
        {pills(profile["headers_missing"]) or "<span style='color:#4caf50'>All checked headers present</span>"}
      </div>
    </div>

  </div>
</div>"""


def _section_risk_ratings():
    ratings = [
        ("CRITICAL", "#ff4444", "Remote code execution, full system compromise, credential exposure at scale. Immediate remediation required before next deployment."),
        ("HIGH",     "#ff9800", "Significant impact on confidentiality, integrity or availability. Remediate within 7 days."),
        ("MEDIUM",   "#ffeb3b", "Limited impact or requiring additional conditions to exploit. Remediate within 30 days."),
        ("LOW",      "#4caf50", "Minimal impact, defence-in-depth improvements. Remediate within 90 days."),
        ("INFO",     "#90caf9", "Informational findings, configuration notes. No direct security risk; review at next opportunity."),
    ]
    rows = ""
    for sev, color, desc in ratings:
        rows += f"""<tr>
          <td><span style="color:{color};font-weight:700">{sev}</span></td>
          <td style="color:#8b949e">{desc}</td>
        </tr>"""
    return f"""
<div class="section">
  <div class="section-title">Risk Rating Definitions</div>
  <table class="risk-table">
    <tr><th>Severity</th><th>Business Impact &amp; Remediation Timeframe</th></tr>
    {rows}
  </table>
</div>"""


def _section_methodology():
    phases = [
        ("P1", "Recon & Fingerprint",  "WHOIS, DNS, HTTP headers, WhatWeb, subdomain enumeration"),
        ("P2", "Headers & TLS",        "Security header audit, cookie flags, SSL/TLS configuration"),
        ("P3", "Dir & File Enum",      "Hidden path discovery, backup files, directory listing checks"),
        ("P4", "Injection Testing",    "XSS (dalfox), SQLi (sqlmap), SSTI, open redirect, CSRF"),
        ("P5", "Auth Testing",         "Login page discovery, error disclosure, rate limiting, brute-force"),
        ("P6", "API & JS Recon",       "JavaScript secret scanning, API endpoint discovery"),
        ("P7", "CMS-Specific",         "WPScan / JoomScan / Droopescan based on detected CMS"),
    ]
    cards = ""
    for phase, name, desc in phases:
        cards += f"""<div class="method-card">
          <div class="phase">{phase}</div>
          <div class="mname">{name}</div>
          <div class="mdesc">{desc}</div>
        </div>"""
    return f"""
<div class="section">
  <div class="section-title">Testing Methodology</div>
  <p style="font-size:0.85rem;color:#8b949e;margin-bottom:1rem">
    Testing followed the <strong style="color:#e6edf3">OWASP Testing Guide v4.2</strong> and
    <strong style="color:#e6edf3">PTES (Penetration Testing Execution Standard)</strong> framework.
    All active testing was performed with written authorisation only.
  </p>
  <div class="method-grid">{cards}</div>
</div>"""


def _section_findings(session):
    if not session.findings:
        return """<div class="section">
          <div class="section-title">Findings</div>
          <p style="color:#8b949e">No findings recorded in this session.</p>
        </div>"""

    sorted_f = sorted(session.findings,
                      key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    html = ""
    for f in sorted_f:
        sev   = f["severity"]
        badge = BADGE_COLORS.get(sev, "")
        ev    = f'<div class="field-label">Evidence</div><div class="evidence">{_esc(f["evidence"])}</div>' if f.get("evidence") else ""
        rem   = f'<div class="field-label">Remediation</div><p>{_esc(f["remediation"])}</p>' if f.get("remediation") else ""
        desc  = f'<p>{_esc(f["description"])}</p>' if f.get("description") else ""
        html += f"""<div class="finding">
          <div class="finding-header">
            <span class="badge" style="{badge}">{sev}</span>
            <span class="finding-title">{_esc(f['title'])}</span>
            <span class="finding-module">{_esc(f.get('module',''))}</span>
          </div>
          <div class="finding-body">
            {desc}{ev}{rem}
            <div class="timestamp">{f.get('timestamp','')[:19]}</div>
          </div>
        </div>"""

    return f"""<div class="section">
      <div class="section-title">Findings</div>
      {html}
    </div>"""


def _section_conclusion(session):
    counts = session.summary()
    sorted_f = sorted(session.findings,
                      key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    steps = ""
    for i, f in enumerate(sorted_f[:8], 1):
        sev   = f["severity"]
        color = {"CRITICAL":"#ff4444","HIGH":"#ff9800","MEDIUM":"#ffeb3b",
                 "LOW":"#4caf50","INFO":"#90caf9"}.get(sev,"#8b949e")
        steps += f"""<div class="next-step">
          <div class="step-num">{i}</div>
          <div>
            <div class="step-text">{_esc(f['title'])}</div>
            <div class="step-sev" style="color:{color}">{sev} — {_esc(f.get('module',''))}</div>
          </div>
        </div>"""

    if not steps:
        steps = "<p style='color:#8b949e;font-size:0.85rem'>No findings to prioritise.</p>"

    return f"""<div class="section">
      <div class="section-title">Conclusion &amp; Recommended Next Steps</div>
      <p style="font-size:0.85rem;color:#8b949e;margin-bottom:1rem">
        The following remediation actions are recommended in priority order.
        Items should be verified via re-testing after fixes are applied.
      </p>
      {steps}
    </div>"""


def _section_cmdlog(session):
    if not session.command_log:
        return ""
    entries = ""
    for entry in session.command_log[-60:]:
        entries += f'<div class="cmd-entry"><span class="cmd-ts">{entry["timestamp"][:19]}</span>{_esc(entry["cmd"][:200])}</div>'
    return f"""<div class="section">
      <div class="section-title">Command Log</div>
      {entries}
    </div>"""


def _section_disclaimer(eng, now):
    tester = _esc(eng.get("tester_name", "the assessor")) or "the assessor"
    return f"""
<div class="disclaimer">
  <strong>Disclaimer</strong><br><br>
  This report was prepared by <strong>{tester}</strong> and is intended solely for the named client
  organisation. The findings reflect the security posture of the target system at the time of
  testing ({now}) and may not represent its complete or future security state. New vulnerabilities
  may emerge after the test date.<br><br>
  This document is <strong>confidential</strong>. Distribution to parties outside the named
  engagement is prohibited without written consent. The assessor accepts no liability for
  actions taken or not taken based on the contents of this report.<br><br>
  All testing was conducted with explicit written authorisation. Unauthorised use of the
  techniques described herein against systems without permission is illegal.
  <br><br>
  <strong>Generated by WebPwn Tools v2.0</strong> &nbsp;|&nbsp; {now}
</div>"""


def _esc(s: str) -> str:
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")
