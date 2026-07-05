"""
Subdomain Enumeration
Sources: crt.sh (certificate transparency, no API key needed)
         + subfinder (if installed on Kali)
         + dnsx for live validation
Results are stored in session.target_profile["subdomains"]
"""
import requests
import subprocess
import re
import socket
from urllib.parse import urlparse
from rich.panel import Panel
from rich.table import Table
from rich.console import Console
from modules.session import Session

UA      = "Mozilla/5.0 (compatible; WebPwnTools/2.0)"
TIMEOUT = 15


def run_subdomain_enum(session: Session, console: Console):
    console.clear()
    domain = urlparse(session.target).netloc or session.target
    # strip www prefix for broader search
    base_domain = re.sub(r'^www\.', '', domain)

    console.print(Panel(
        f"[bold]Subdomain Enumeration[/bold]  →  [cyan]{base_domain}[/cyan]",
        border_style="bright_blue"
    ))
    console.print()

    found: set[str] = set()

    found |= _crtsh(base_domain, console)
    found |= _subfinder(base_domain, console)

    # Validate which ones resolve (live check)
    live = _validate_live(found, console)

    # Store in session profile
    for sub in sorted(live):
        session.append_profile("subdomains", sub)

    # Summary table
    if live:
        console.print(f"\n  [bright_green]✓ {len(live)} live subdomains found:[/bright_green]\n")
        t = Table(show_header=True, header_style="bold cyan",
                  border_style="dim", show_lines=True)
        t.add_column("Subdomain",   style="cyan",  width=40)
        t.add_column("IP",          style="white", width=18)
        t.add_column("Status",      style="green", width=10)
        for sub, ip in sorted(live.items()):
            t.add_row(sub, ip, "[green]LIVE[/green]")
        console.print(t)
    else:
        console.print("  [dim]No live subdomains found.[/dim]")

    console.print()
    console.print("[dim]Press Enter to return to menu...[/dim]")
    input()


# ── Sources ──────────────────────────────────────────────────────────────────

def _crtsh(domain: str, console: Console) -> set:
    """Query crt.sh certificate transparency log (passive, no key needed)."""
    console.print("[bold cyan]  ── crt.sh (Certificate Transparency) ────[/bold cyan]")
    found = set()
    try:
        r = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            headers={"User-Agent": UA},
            timeout=TIMEOUT
        )
        if r.status_code == 200:
            entries = r.json()
            for entry in entries:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower()
                    # Skip wildcards and unrelated domains
                    if name.startswith("*"):
                        name = name.lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        found.add(name)
            console.print(f"  [dim]crt.sh returned {len(found)} unique names[/dim]")
        else:
            console.print(f"  [yellow]  crt.sh returned {r.status_code}[/yellow]")
    except requests.Timeout:
        console.print("  [yellow]  crt.sh timed out[/yellow]")
    except Exception as e:
        console.print(f"  [red]  crt.sh error: {e}[/red]")
    console.print()
    return found


def _subfinder(domain: str, console: Console) -> set:
    """Run subfinder if installed (passive mode, no bruteforce)."""
    console.print("[bold cyan]  ── subfinder ─────────────────────────────[/bold cyan]")
    found = set()
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-all"],
            capture_output=True, text=True, timeout=60
        )
        for line in result.stdout.splitlines():
            line = line.strip().lower()
            if line and (line.endswith(f".{domain}") or line == domain):
                found.add(line)
        if found:
            console.print(f"  [dim]subfinder found {len(found)} names[/dim]")
        else:
            console.print("  [dim]subfinder: no additional results[/dim]")
    except FileNotFoundError:
        console.print("  [dim]subfinder not installed — skipping[/dim]")
        console.print("  [dim]Install: apt install subfinder[/dim]")
    except subprocess.TimeoutExpired:
        console.print("  [yellow]  subfinder timed out[/yellow]")
    except Exception as e:
        console.print(f"  [red]  subfinder error: {e}[/red]")
    console.print()
    return found


def _validate_live(subdomains: set, console: Console) -> dict:
    """DNS resolve each subdomain — return dict of {subdomain: ip} for live ones."""
    console.print("[bold cyan]  ── Live validation (DNS resolve) ──────────[/bold cyan]")
    if not subdomains:
        console.print("  [dim]Nothing to validate.[/dim]")
        console.print()
        return {}

    live = {}
    console.print(f"  [dim]Checking {len(subdomains)} subdomains...[/dim]")
    for sub in sorted(subdomains):
        try:
            ip = socket.gethostbyname(sub)
            live[sub] = ip
            console.print(f"  [bright_green]✓[/bright_green] {sub:<40} {ip}")
        except socket.gaierror:
            pass   # not live — silently skip
        except Exception:
            pass
    console.print()
    return live
