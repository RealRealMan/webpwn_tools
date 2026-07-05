"""
Module 1 — Recon & Fingerprinting
Runs: WHOIS, DNS lookup, HTTP header grab, WhatWeb, subdomain enum.
Populates session.target_profile with all discovered data.
"""
import subprocess
import socket
import re
import requests
from urllib.parse import urlparse
from rich.panel import Panel
from rich.table import Table
from rich.console import Console
from rich.prompt import Confirm
from modules.session import Session
from modules.subdomain_enum import run_subdomain_enum

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
    session.set_profile("domain", domain)

    _run_whois(domain, session, console)
    _run_dns(domain, session, console)
    _run_headers(session, console)
    _run_whatweb(session, console)

    # Ask if user wants subdomain enum (can be slow)
    console.print()
    if Confirm.ask("  Run subdomain enumeration? (crt.sh + subfinder)", default=True):
        run_subdomain_enum(session, console)
        return   # subdomain_enum has its own "press enter" prompt

    console.print()
    console.print("[dim]Press Enter to return to menu...[/dim]")
    input()


def _run_whois(domain: str, session: Session, console: Console):
    console.print("[bold cyan]  ── WHOIS ─────────────────────────────────[/bold cyan]")
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=15
        )
        output = result.stdout

        patterns = {
            "Registrar":      r"Registrar:\s*(.+)",
            "Creation Date":  r"Creation Date:\s*(.+)",
            "Updated Date":   r"Updated Date:\s*(.+)",
            "Expiry Date":    r"Registry Expiry Date:\s*(.+)|Expiry Date:\s*(.+)",
            "Name Server":    r"Name Server:\s*(.+)",
            "Registrant Org": r"Registrant Organization:\s*(.+)",
        }
        fields = {}
        for label, pattern in patterns.items():
            m = re.search(pattern, output, re.IGNORECASE)
            if m:
                val = next((v for v in m.groups() if v), "").strip()
                fields[label] = val

        # Write to profile
        session.set_profile("whois_registrar", fields.get("Registrar", ""))
        session.set_profile("whois_created",   fields.get("Creation Date", "")[:10] if fields.get("Creation Date") else "")
        session.set_profile("whois_expiry",    fields.get("Expiry Date", "")[:10] if fields.get("Expiry Date") else "")
        session.set_profile("whois_org",       fields.get("Registrant Org", ""))

        if fields:
            t = Table(show_header=False, border_style="dim")
            t.add_column("Key",   style="dim", width=20)
            t.add_column("Value", style="white")
            for k, v in fields.items():
                t.add_row(k, v)
            console.print(t)
        else:
            console.print("  [dim]No WHOIS data extracted (may be rate-limited)[/dim]")

        session.log_command(f"whois {domain}", output[:500])

    except FileNotFoundError:
        console.print("  [yellow]  whois not installed — apt install whois[/yellow]")
    except Exception as e:
        console.print(f"  [red]  WHOIS error: {e}[/red]")
    console.print()


def _run_dns(domain: str, session: Session, console: Console):
    console.print("[bold cyan]  ── DNS Lookup ────────────────────────────[/bold cyan]")
    try:
        ips = list({addr[4][0] for addr in socket.getaddrinfo(domain, None)})
        for ip in ips:
            console.print(f"  [green]A[/green]     {ip}")
            session.append_profile("ip_addresses", ip)
            session.add_finding("INFO", f"IP Address: {ip}",
                                f"{domain} resolves to {ip}",
                                evidence=ip, module="Recon")
    except Exception:
        console.print("  [dim]  Could not resolve domain[/dim]")

    for rtype in ["MX", "NS", "TXT"]:
        try:
            r = subprocess.run(
                ["dig", "+short", domain, rtype],
                capture_output=True, text=True, timeout=8
            )
            lines = [l.strip() for l in r.stdout.strip().splitlines() if l.strip()]
            for line in lines[:4]:
                console.print(f"  [green]{rtype:<5}[/green] {line}")
            # Write to profile
            key = f"dns_{rtype.lower()}"
            for line in lines:
                session.append_profile(key, line)
            session.log_command(f"dig +short {domain} {rtype}", r.stdout)
        except FileNotFoundError:
            break
        except Exception:
            pass
    console.print()


def _run_headers(session: Session, console: Console):
    console.print("[bold cyan]  ── HTTP Response Headers ─────────────────[/bold cyan]")
    try:
        proxies = session.proxy_dict()
        r = requests.get(session.target,
                         headers={"User-Agent": UA},
                         proxies=proxies,
                         timeout=TIMEOUT,
                         verify=False,
                         allow_redirects=True)

        interesting = [
            "server", "x-powered-by", "x-generator", "x-aspnet-version",
            "x-aspnetmvc-version", "content-type", "set-cookie", "location",
            "x-frame-options", "content-security-policy",
            "strict-transport-security", "x-content-type-options",
            "referrer-policy", "permissions-policy", "via", "x-cache",
            "cf-ray", "x-served-by",
        ]

        t = Table(show_header=False, border_style="dim")
        t.add_column("Header", style="dim", width=32)
        t.add_column("Value",  style="white")

        for hdr in interesting:
            val = r.headers.get(hdr)
            if val:
                t.add_row(hdr, val[:120])

        console.print(t)
        console.print(f"\n  [dim]Status: {r.status_code}  |  Final URL: {r.url}[/dim]")

        # Populate profile
        server = r.headers.get("server", "")
        session.set_profile("server", server)
        for hdr in ["x-powered-by", "x-generator", "x-aspnet-version"]:
            val = r.headers.get(hdr, "")
            if val:
                session.append_profile("technologies", val)

        # CDN detection from headers
        cdn_signals = {
            "Cloudflare": ["cf-ray", "cf-cache-status"],
            "Fastly":     ["x-served-by", "x-fastly-request-id"],
            "Varnish":    ["x-varnish"],
            "AWS CloudFront": ["x-amz-cf-id"],
            "Akamai":    ["x-akamai-request-id"],
        }
        for cdn, hdrs in cdn_signals.items():
            if any(h in {k.lower() for k in r.headers} for h in hdrs):
                session.set_profile("cdn", cdn)
                console.print(f"  [cyan]  CDN detected: {cdn}[/cyan]")
                break

        # Server version disclosure
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
            capture_output=True, text=True, timeout=60
        )
        output = result.stdout.strip()
        if output:
            # Parse WhatWeb output into individual technology tokens
            parts = re.split(r'(?=\[)', output)
            for part in parts:
                part = part.strip()
                if part and not part.startswith("http"):
                    console.print(f"  {part}")
                    # Extract tech names into profile
                    m = re.match(r'\[([^\]]+)\]', part)
                    if m:
                        session.append_profile("technologies", m.group(1))
        else:
            console.print("  [dim]No WhatWeb output[/dim]")
        session.log_command(f"whatweb {session.target}", output)
    except FileNotFoundError:
        console.print("  [yellow]  whatweb not found — apt install whatweb[/yellow]")
    except subprocess.TimeoutExpired:
        console.print("  [yellow]  WhatWeb timed out (60s)[/yellow]")
    except Exception as e:
        console.print(f"  [red]  WhatWeb error: {e}[/red]")
    console.print()
