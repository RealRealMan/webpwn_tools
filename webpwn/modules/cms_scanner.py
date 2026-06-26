"""Module 7 — CMS Scanner (WordPress / Joomla / Drupal)"""
import subprocess
from rich.panel import Panel
from rich.console import Console
from rich.prompt import Prompt
from modules.session import Session


def run_cms_scanner(session: Session, console: Console):
    console.clear()
    cms = session.cms or "Unknown"
    console.print(Panel(
        f"[bold]CMS Scanner[/bold]  →  [cyan]{session.target}[/cyan]  [dim]CMS: {cms}[/dim]",
        border_style="bright_blue"
    ))
    console.print()

    if not session.cms:
        console.print("  [yellow]  CMS not detected. Running WPScan as default.[/yellow]")
        console.print("  [dim]  Set target again to re-run CMS detection.[/dim]")
        console.print()

    dispatch = {
        "WordPress": _run_wpscan,
        "Joomla":    _run_joomscan,
        "Drupal":    _run_droopescan,
    }

    scanner = dispatch.get(session.cms, _run_wpscan)
    scanner(session, console)

    console.print()
    console.print("[dim]Press Enter to return to menu...[/dim]")
    input()


def _run_wpscan(session: Session, console: Console):
    console.print("[bold cyan]  ── WPScan ────────────────────────────────[/bold cyan]")

    if not session.wpscan_api:
        console.print("  [yellow]  WPScan API token not set (CVE lookup disabled).[/yellow]")
        console.print("  [dim]  Get a free token at https://wpscan.com — set in Settings [0][/dim]")
        console.print()

    console.print("  [bold]Scan mode:[/bold]")
    console.print("  [1] Basic (version + passive plugin detection)")
    console.print("  [2] Full  (aggressive plugin + theme + user enum)")
    console.print("  [3] Users only")
    mode = Prompt.ask("  Mode", choices=["1","2","3"], default="1")

    proxy_flags = ["--proxy", f"http://{session.proxy}"] if session.proxy else []
    api_flags   = ["--api-token", session.wpscan_api] if session.wpscan_api else []

    enumerate_map = {
        "1": ["p"],
        "2": ["ap", "at", "u", "cb", "dbe"],
        "3": ["u"],
    }
    enum = enumerate_map[mode]

    cmd = [
        "wpscan",
        "--url", session.target,
        "--no-banner",
        "--enumerate", ",".join(enum),
    ]
    if mode == "2":
        cmd += ["--plugins-detection", "aggressive",
                "--themes-detection", "aggressive"]
    cmd += api_flags + proxy_flags

    console.print(f"\n  [dim]$ {' '.join(cmd)}[/dim]\n")

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in proc.stdout:
            line = line.rstrip()
            if not line.strip():
                continue
            ll = line.lower()
            if "[!]" in line or "vulnerability" in ll or "cve" in ll:
                console.print(f"  [bold red]{line}[/bold red]")
                session.add_finding("HIGH", line.strip()[:100],
                                    "WPScan identified a vulnerability.",
                                    evidence=line.strip(),
                                    remediation="Update the affected plugin/theme/core to the latest version.",
                                    module="CMS Scanner")
            elif "[+]" in line:
                console.print(f"  [bright_green]{line}[/bright_green]")
            elif "[i]" in line or "[*]" in line:
                console.print(f"  [dim]{line}[/dim]")
            else:
                console.print(f"  {line}")
        proc.wait()
    except FileNotFoundError:
        console.print("  [yellow]  wpscan not found.[/yellow]")
        console.print("  [dim]  Install: gem install wpscan  (pre-installed on Kali)[/dim]")
    except Exception as e:
        console.print(f"  [red]  WPScan error: {e}[/red]")
    console.print()


def _run_joomscan(session: Session, console: Console):
    console.print("[bold cyan]  ── JoomScan (Joomla) ─────────────────────[/bold cyan]")
    cmd = ["joomscan", "-u", session.target, "--ec"]
    console.print(f"  [dim]$ {' '.join(cmd)}[/dim]\n")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        for line in result.stdout.splitlines():
            if "vulnerab" in line.lower() or "[!]" in line:
                console.print(f"  [bold red]{line}[/bold red]")
                session.add_finding("HIGH", line.strip()[:100], "",
                                    evidence=line.strip(), module="CMS Scanner")
            elif line.strip():
                console.print(f"  [dim]{line}[/dim]")
    except FileNotFoundError:
        console.print("  [yellow]  joomscan not found.[/yellow]")
        console.print("  [dim]  Install: apt install joomscan  (Kali)[/dim]")
    except Exception as e:
        console.print(f"  [red]  JoomScan error: {e}[/red]")
    console.print()


def _run_droopescan(session: Session, console: Console):
    console.print("[bold cyan]  ── Droopescan (Drupal) ───────────────────[/bold cyan]")
    cmd = ["droopescan", "scan", "drupal", "-u", session.target]
    console.print(f"  [dim]$ {' '.join(cmd)}[/dim]\n")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        for line in result.stdout.splitlines():
            if "[+]" in line and "vulnerab" in line.lower():
                console.print(f"  [bold red]{line}[/bold red]")
                session.add_finding("HIGH", line.strip()[:100], "",
                                    evidence=line.strip(), module="CMS Scanner")
            elif line.strip():
                console.print(f"  {line}")
    except FileNotFoundError:
        console.print("  [yellow]  droopescan not found.[/yellow]")
        console.print("  [dim]  Install: pip install droopescan[/dim]")
    except Exception as e:
        console.print(f"  [red]  droopescan error: {e}[/red]")
    console.print()
