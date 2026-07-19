"""
Module 1 — Recon & Fingerprinting
Stores WHOIS, DNS, tech fingerprint into session for reporter use.
"""
import subprocess
import socket
import re
import requests
from urllib.parse import urlparse
from rich.panel import Panel
from rich.table import Table
from rich.console import Console
from modules.session import Session

TIMEOUT = 10
UA = "Mozilla/5.0 (compatible; WebPwnTools/2.0; security-assessment)"


def run_recon(session: Session, console: Console):
    console.clear()
    console.print(Panel(
        f"[bold]Recon & Fingerprinting[/bold]  →  [cyan]{session.target}[/cyan]",
        border_style="bright_blue"
    ))
    console.print()

    domain = urlparse(session.target).netloc or session.target

    _run_whois(domain, session, console)
    _run_dns(domain, session, console)
    _run_headers(session, console)
    _run_whatweb(session, console)

    console.print()
    console.print("[dim]Press Enter to return to menu...[/dim]")
    input()


def _run_whois(domain: str, session: Session, console: Console):
    console.print("[bold cyan]  ── WHOIS ─────────────────────────────────[/bold cyan]")
    try:
        result = subprocess.run(["whois", domain],
                                capture_output=True, text=True, timeout=15)
        output = result.stdout

        patterns = {
            "Registrar":      r"Registrar:\s*(.+)",
            "Creation Date":  r"Creation Date:\s*(.+)",
            "Expiry Date":    r"Registry Expiry Date:\s*(.+)|Expiry Date:\s*(.+)",
            "Registrant Org": r"Registrant Organization:\s*(.+)",
            "Name Servers":   r"Name Server:\s*(.+)",
        }

        fields = {}
        for label, pattern in patterns.items():
            m = re.search(pattern, output, re.IGNORECASE)
            if m:
                val = next((v for v in m.groups() if v), "").strip()
                if val:
                    fields[label] = val

        # Fix #9: Store in session for reporter
        session.whois_data.update(fields)

        if fields:
            t = Table(show_header=False, border_style="dim", show_lines=False)
            t.add_column("Key",   style="dim", width=20)
            t.add_column("Value", style="white")
            for k, v in fields.items():
                t.add_row(k, v)
            console.print(t)
        else:
            console.print("  [dim]No WHOIS data extracted (may be rate-limited)[/dim]")

        session.log_command(f"whois {domain}", output[:500])

    except FileNotFoundError:
        console.print("  [yellow]  whois not installed. Install: apt install whois[/yellow]")
    except Exception as e:
        console.print(f"  [red]  WHOIS error: {e}[/red]")
    console.print()


def _run_dns(domain: str, session: Session, console: Console):
    console.print("[bold cyan]  ── DNS Lookup ────────────────────────────[/bold cyan]")
    try:
        try:
            ips = list({addr[4][0] for addr in socket.getaddrinfo(domain, None)})
            for ip in ips:
                console.print(f"  [green]A[/green]     {ip}")
                session.add_finding("INFO", f"IP Address: {ip}",
                                    f"{domain} resolves to {ip}",
                                    evidence=ip, module="Recon")
        except Exception:
            console.print("  [dim]Could not resolve domain[/dim]")

        for rtype in ["MX", "NS", "TXT"]:
            try:
                r = subprocess.run(["dig", "+short", domain, rtype],
                                   capture_output=True, text=True, timeout=8)
                lines = [l.strip() for l in r.stdout.strip().splitlines() if l.strip()]
                for line in lines[:4]:
                    console.print(f"  [green]{rtype:<5}[/green] {line}")

                # Fix #9: store DNS in session.whois_data for reporter
                if lines:
                    session.whois_data[rtype.lower()] = lines

                session.log_command(f"dig +short {domain} {rtype}", r.stdout)
            except FileNotFoundError:
                break
            except Exception:
                pass
    except Exception as e:
        console.print(f"  [red]  DNS error: {e}[/red]")
    console.print()


def _run_headers(session: Session, console: Console):
    console.print("[bold cyan]  ── HTTP Response Headers ─────────────────[/bold cyan]")
    try:
        proxies = session.proxy_dict()
        r = requests.get(session.target,
                         headers={"User-Agent": UA},
                         proxies=proxies, timeout=TIMEOUT,
                         verify=False, allow_redirects=True)

        interesting = [
            "server", "x-powered-by", "x-generator", "x-aspnet-version",
            "content-type", "set-cookie", "location",
            "x-frame-options", "content-security-policy",
            "strict-transport-security", "x-content-type-options",
            "referrer-policy", "permissions-policy",
        ]

        t = Table(show_header=False, border_style="dim", show_lines=False)
        t.add_column("Header", style="dim", width=32)
        t.add_column("Value",  style="white")

        for hdr in interesting:
            val = r.headers.get(hdr)
            if val:
                t.add_row(hdr, val[:120])

        console.print(t)
        console.print(f"\n  [dim]Status: {r.status_code}  |  Final URL: {r.url}[/dim]")

        # Flag version leakage
        for hdr in ["server", "x-powered-by", "x-aspnet-version"]:
            val = r.headers.get(hdr, "")
            if val and any(c.isdigit() for c in val):
                session.add_finding(
                    "LOW", f"Version disclosed in {hdr} header",
                    f"Header '{hdr}: {val}' reveals software version.",
                    evidence=f"{hdr}: {val}",
                    remediation=f"Remove or genericise the {hdr} header.",
                    module="Recon"
                )
                console.print(f"  [yellow]  ⚠ Version disclosure: {hdr}: {val}[/yellow]")

        session.log_command(f"curl -sI {session.target}", str(dict(r.headers)))

    except Exception as e:
        console.print(f"  [red]  Header fetch error: {e}[/red]")
    console.print()


def _run_whatweb(session: Session, console: Console):
    console.print("[bold cyan]  ── WhatWeb Technology Fingerprint ────────[/bold cyan]")
    try:
        result = subprocess.run(
            ["whatweb", "--color=never", session.target]
            + (["--proxy", session.proxy] if session.proxy else []),
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout.strip()
        if output:
            # Fix #7: Parse WhatWeb output into clean tech tags for session
            # WhatWeb format: URL [status] Plugin[value], Plugin[value]...
            raw_tags = re.findall(r'(\w[\w\-\.]+)\[([^\]]*)\]', output)
            clean_techs = []
            skip_keys = {"HTTPServer", "IP", "Country", "Email", "Script",
                         "UncommonHeaders", "HTML5", "JQuery", "Via-Proxy",
                         "Cache-Control", "Strict-Transport-Security"}
            for key, val in raw_tags:
                if key in skip_keys:
                    continue
                tag = val.strip() if val.strip() else key
                if tag and len(tag) < 60:
                    clean_techs.append(tag)

            # Store in session for reporter
            session.tech_data = list(dict.fromkeys(clean_techs))  # deduplicate

            # Display
            parts = re.split(r'(?=\[)', output)
            for part in parts:
                part = part.strip()
                if part and part != session.target:
                    console.print(f"  {part}")
        else:
            console.print("  [dim]No WhatWeb output[/dim]")

        session.log_command(f"whatweb {session.target}", output)

    except FileNotFoundError:
        console.print("  [yellow]  whatweb not found. Install: apt install whatweb[/yellow]")
    except Exception as e:
        console.print(f"  [red]  WhatWeb error: {e}[/red]")
    console.print()
