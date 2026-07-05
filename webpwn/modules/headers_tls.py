"""
Module 2 — HTTP Security Headers & TLS Analysis
Checks CSP, HSTS, X-Frame-Options, X-Content-Type-Options, cookie flags, SSL grade.
"""
import subprocess
import requests
from urllib.parse import urlparse
from rich.panel import Panel
from rich.table import Table
from rich.console import Console
from modules.session import Session

TIMEOUT = 10
UA = "Mozilla/5.0 (compatible; WebPwnTools/2.0; security-assessment)"

SECURITY_HEADERS = {
    "strict-transport-security": {
        "required": True,
        "desc": "HSTS — forces HTTPS, prevents downgrade attacks",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "content-security-policy": {
        "required": True,
        "desc": "CSP — mitigates XSS by restricting resource origins",
        "remediation": "Add a Content-Security-Policy header. Start with default-src 'self'.",
    },
    "x-frame-options": {
        "required": True,
        "desc": "Prevents clickjacking via iframe embedding",
        "remediation": "Add: X-Frame-Options: SAMEORIGIN",
    },
    "x-content-type-options": {
        "required": True,
        "desc": "Prevents MIME-type sniffing",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    "referrer-policy": {
        "required": False,
        "desc": "Controls referrer information sent to other origins",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "required": False,
        "desc": "Restricts browser feature access (camera, mic, etc.)",
        "remediation": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    },
    "x-xss-protection": {
        "required": False,
        "desc": "Legacy XSS filter (deprecated; CSP is preferred)",
        "remediation": "Use CSP instead. If kept: X-XSS-Protection: 1; mode=block",
    },
}


def run_headers_tls(session: Session, console: Console):
    console.clear()
    console.print(Panel(
        f"[bold]Headers & TLS Analysis[/bold]  →  [cyan]{session.target}[/cyan]",
        border_style="bright_blue"
    ))
    console.print()

    _check_security_headers(session, console)
    _check_cookies(session, console)
    _run_testssl(session, console)

    console.print()
    console.print("[dim]Press Enter to return to menu...[/dim]")
    input()


def _check_security_headers(session: Session, console: Console):
    console.print("[bold cyan]  ── Security Headers ──────────────────────[/bold cyan]")
    try:
        proxies = session.proxy_dict()
        r = requests.get(session.target,
                         headers={"User-Agent": UA},
                         proxies=proxies,
                         timeout=TIMEOUT,
                         verify=False,
                         allow_redirects=True)

        hdrs = {k.lower(): v for k, v in r.headers.items()}

        t = Table(show_header=True, header_style="bold cyan",
                  border_style="dim", show_lines=True)
        t.add_column("Header",   width=32)
        t.add_column("Status",   width=10)
        t.add_column("Value / Note", width=50)

        for hdr, meta in SECURITY_HEADERS.items():
            val = hdrs.get(hdr)
            if val:
                status = "[bright_green]✓ PRESENT[/bright_green]"
                display = val[:60] + ("…" if len(val) > 60 else "")
                session.append_profile("headers_present", hdr)
            else:
                sev = "HIGH" if meta["required"] else "MEDIUM"
                status = f"[{'bold red' if meta['required'] else 'yellow'}]✗ MISSING[/{'bold red' if meta['required'] else 'yellow'}]"
                display = f"[dim]{meta['desc']}[/dim]"
                session.append_profile("headers_missing", hdr)
                session.add_finding(
                    sev,
                    f"Missing security header: {hdr}",
                    meta["desc"],
                    evidence=f"Header '{hdr}' not present in HTTP response",
                    remediation=meta["remediation"],
                    module="Headers & TLS"
                )

            t.add_row(hdr, status, display)

        console.print(t)
        session.log_command(f"curl -sI {session.target}", str(dict(r.headers)))

    except Exception as e:
        console.print(f"  [red]  Error fetching headers: {e}[/red]")

    console.print()


def _check_cookies(session: Session, console: Console):
    console.print("[bold cyan]  ── Cookie Security Flags ─────────────────[/bold cyan]")
    try:
        proxies = session.proxy_dict()
        r = requests.get(session.target,
                         headers={"User-Agent": UA},
                         proxies=proxies,
                         timeout=TIMEOUT,
                         verify=False,
                         allow_redirects=True)

        if not r.cookies:
            console.print("  [dim]No cookies set on initial request.[/dim]")
        else:
            t = Table(show_header=True, header_style="bold cyan",
                      border_style="dim", show_lines=True)
            t.add_column("Cookie",    width=24)
            t.add_column("Secure",    width=8)
            t.add_column("HttpOnly",  width=10)
            t.add_column("SameSite",  width=10)

            for cookie in r.cookies:
                secure_str   = "[green]✓[/green]" if cookie.secure else "[red]✗[/red]"
                httponly_str = "[green]✓[/green]" if cookie.has_nonstandard_attr("HttpOnly") else "[red]✗[/red]"
                samesite     = cookie.get_nonstandard_attr("SameSite") or "[dim]not set[/dim]"
                t.add_row(cookie.name[:22], secure_str, httponly_str, samesite)

                if not cookie.secure:
                    session.add_finding(
                        "MEDIUM",
                        f"Cookie '{cookie.name}' missing Secure flag",
                        "Cookie can be transmitted over HTTP, exposing it to interception.",
                        evidence=f"Set-Cookie: {cookie.name}=...",
                        remediation="Add Secure flag to all cookies.",
                        module="Headers & TLS"
                    )

            console.print(t)

    except Exception as e:
        console.print(f"  [red]  Cookie check error: {e}[/red]")

    console.print()


def _run_testssl(session: Session, console: Console):
    console.print("[bold cyan]  ── TLS / SSL Analysis (testssl.sh) ───────[/bold cyan]")
    domain = urlparse(session.target).netloc or session.target
    cmd = ["testssl.sh", "--color", "0", "--severity", "HIGH", domain]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=90
        )
        output = result.stdout

        # Print only HIGH/CRITICAL lines
        for line in output.splitlines():
            line_l = line.lower()
            if any(kw in line_l for kw in ["critical", "high", "medium", "low", "ok", "not ok"]):
                if "critical" in line_l or "not ok" in line_l:
                    console.print(f"  [bold red]{line.strip()}[/bold red]")
                elif "high" in line_l:
                    console.print(f"  [yellow]{line.strip()}[/yellow]")
                elif "ok" in line_l:
                    console.print(f"  [green]{line.strip()}[/green]")
                else:
                    console.print(f"  [dim]{line.strip()}[/dim]")

        session.log_command(" ".join(cmd), output[:1000])

    except FileNotFoundError:
        console.print("  [yellow]  testssl.sh not found.[/yellow]")
        console.print("  [dim]  Install: apt install testssl.sh  OR  git clone https://github.com/drwetter/testssl.sh[/dim]")
        console.print()
        console.print("  [dim]  Quick alternative (online): https://www.ssllabs.com/ssltest/analyze.html[/dim]")
        console.print(f"  [cyan]  → https://www.ssllabs.com/ssltest/analyze.html?d={urlparse(session.target).netloc}[/cyan]")
    except subprocess.TimeoutExpired:
        console.print("  [yellow]  testssl.sh timed out (>90s). Try running manually:[/yellow]")
        console.print(f"  [dim]  testssl.sh {domain}[/dim]")
    except Exception as e:
        console.print(f"  [red]  testssl error: {e}[/red]")

    console.print()
