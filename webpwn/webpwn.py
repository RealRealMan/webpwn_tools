#!/usr/bin/env python3
"""
WebPwn Tools v2.0 - Universal Web Penetration Testing Toolkit
Authorized use only. For ethical security testing with written permission.
"""

import sys
import time
import argparse
import os
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
from rich.prompt import Prompt, Confirm
from rich import print as rprint
from rich.table import Table
from rich.align import Align
from rich.live import Live
from rich.columns import Columns
from modules.session import Session
from modules.recon import run_recon
from modules.headers_tls import run_headers_tls
from modules.dir_enum import run_dir_enum
from modules.injection import run_injection
from modules.auth import run_auth
from modules.api_recon import run_api_recon
from modules.cms_scanner import run_cms_scanner
from modules.user_enum import run_user_enum
from modules.reporter import generate_report
from modules.settings import show_settings, load_config, save_config
from modules.cms_detect import detect_cms
from modules.subdomain_enum import run_subdomain_enum

console = Console()

VERSION = "2.0"
BANNER_SIMPLE = "WebPwn Tools"

MODULES = [
    ("1", "Recon & Fingerprint",    "WHOIS, DNS, headers, tech stack, subdomains", "passive",  "whatweb / dig"),
    ("2", "Headers & TLS",          "CSP, HSTS, SSL rating, cookie flags",          "passive",  "testssl / curl"),
    ("3", "Dir & File Enum",        "Hidden paths, backups, open directories",       "active",   "gobuster"),
    ("4", "Injection Tests",        "XSS, SQLi, CSRF, SSTI, open redirect",          "active",   "dalfox / sqlmap"),
    ("5", "Auth Testing",           "Login bypass, brute-force, session mgmt",       "active",   "hydra / burp"),
    ("6", "API & JS Recon",         "JS files, API endpoints, exposed secrets",      "passive",  "custom"),
    ("7", "CMS Scanner",            "Plugins, themes, users, CVEs",                  "active",   "wpscan / joomscan"),
    ("8", "User Enumeration",       "CMS user discovery via API & pages",            "semi",     "cms-specific"),
    ("9", "Generate Report",        "Export all findings → HTML report",             "output",   "built-in"),
    ("10", "Subdomain Enum",         "crt.sh + subfinder + live DNS validation",      "passive",  "subfinder"),
    ("0", "Settings",               "Target, proxy, engagement info, API keys",      "config",   "config.yaml"),
]

SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "dim white",
}


def splash_screen():
    """Animated splash screen with progress bar."""
    console.clear()

    steps = [
        "Loading universal recon module...",
        "Loading CMS detection engine...",
        "Loading WordPress scanner...",
        "Loading Joomla / Drupal modules...",
        "Loading injection tester...",
        "Loading auth & API modules...",
        "Loading report generator...",
        "Checking dependencies...",
        "All modules ready.",
    ]

    # Print banner
    console.print()
    banner_text = Text(BANNER_SIMPLE, style="bold bright_blue", justify="center")
    console.print(Align.center(banner_text, vertical="middle"),
                  style="bold bright_blue")

    subtitle = Text(f"v{VERSION}  ·  Universal Web Penetration Toolkit", justify="center")
    subtitle.stylize("dim cyan")
    console.print(Align.center(subtitle))

    auth_warn = Text("⚠  Authorized use only  |  For ethical security testing only", justify="center")
    auth_warn.stylize("dim yellow")
    console.print(Align.center(auth_warn))
    console.print()

    # Progress bar
    with Progress(
        TextColumn("  [cyan]{task.description}[/cyan]"),
        BarColumn(bar_width=50, complete_style="green", finished_style="bright_green"),
        TextColumn("[green]{task.percentage:>3.0f}%[/green]"),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("Initializing...", total=len(steps))
        for msg in steps:
            progress.update(task, description=msg)
            time.sleep(0.25)
            progress.advance(task)
        progress.update(task, description="[bright_green]All modules ready.[/bright_green]")

    console.print()
    time.sleep(0.3)


def print_main_menu(session: Session):
    """Print the main menu with session info."""
    console.clear()

    # Header panel
    cms_str = f"[bright_green]{session.cms}[/bright_green]" if session.cms else "[dim]unknown[/dim]"
    proxy_str = f"[bright_green]ON ({session.proxy})[/bright_green]" if session.proxy else "[dim]OFF[/dim]"
    target_str = f"[bright_cyan]{session.target}[/bright_cyan]" if session.target else "[dim red]not set[/dim red]"

    header = (
        f"  [bold]Target:[/bold] {target_str}   "
        f"[bold]CMS:[/bold] {cms_str}   "
        f"[bold]Proxy:[/bold] {proxy_str}\n"
        f"  [bold]Session:[/bold] [dim]{session.session_id}[/dim]   "
        f"[bold]Findings:[/bold] [yellow]{len(session.findings)}[/yellow]   "
        f"[bold]Reports:[/bold] [dim]{session.report_dir}[/dim]"
    )

    console.print(Panel(
        header,
        title=f"[bold bright_blue]WebPwn Tools v{VERSION}[/bold bright_blue]",
        border_style="bright_blue",
        padding=(0, 1),
    ))
    console.print()

    # Universal modules section
    console.print("  [bold dim]── UNIVERSAL MODULES (all CMS) ──────────────────────────────[/bold dim]")
    console.print()

    universal = MODULES[:7]    # 1-6 + s
    cms_specific = MODULES[7:9]
    output_modules = MODULES[9:]

    _print_module_table(universal)
    console.print()

    # CMS-specific section
    cms_label = f"CMS-specific"
    if session.cms:
        cms_label += f" (loaded: {session.cms})"
    console.print(f"  [bold dim]── {cms_label.upper()} {'─' * max(1, 48 - len(cms_label))}[/bold dim]")
    console.print()
    _print_module_table(cms_specific)
    console.print()

    # Output section
    console.print("  [bold dim]── OUTPUT & CONFIG ──────────────────────────────────────────[/bold dim]")
    console.print()
    _print_module_table(output_modules)
    console.print()

    # Footer hints — clearly visible shortcut bar
    from rich.table import Table as _T
    _ft = _T.grid(padding=(0, 3))
    _ft.add_row(
        "[bold bright_green][ r ][/bold bright_green] [white]Set / change target[/white]",
        "[bold bright_yellow][ p ][/bold bright_yellow] [white]Toggle Burp proxy[/white]",
        "[bold cyan][ c ][/bold cyan] [white]Clear findings[/white]",
        "[bold red][ q ][/bold red] [white]Quit[/white]",
    )
    console.rule("[dim]Shortcuts[/dim]")
    console.print(_ft)
    console.print()


def _print_module_table(modules):
    """Helper to print a formatted module list."""
    for key, name, desc, mode, tools in modules:
        mode_styles = {
            "passive": "[bright_green]passive[/bright_green]",
            "active":  "[bright_red]active[/bright_red]",
            "semi":    "[yellow]semi-passive[/yellow]",
            "output":  "[cyan]output[/cyan]",
            "config":  "[dim]config[/dim]",
        }
        mode_tag = mode_styles.get(mode, mode)
        console.print(
            f"  [bright_green][{key}][/bright_green] "
            f"[bold white]{name:<26}[/bold white] "
            f"[dim]{desc:<44}[/dim] "
            f"{mode_tag}  [dim cyan]{tools}[/dim cyan]"
        )


def run_module(choice: str, session: Session):
    """Dispatch to the correct module."""
    dispatch = {
        "1": run_recon,
        "2": run_headers_tls,
        "3": run_dir_enum,
        "4": run_injection,
        "5": run_auth,
        "6": run_api_recon,
        "7": run_cms_scanner,
        "8": run_user_enum,
        "10": run_subdomain_enum,
    }

    if choice in dispatch:
        if not session.target:
            console.print("[bold red]  ✗ No target set. Use [r] to set a target first.[/bold red]")
            time.sleep(1.5)
            return
        dispatch[choice](session, console)

    elif choice == "9":
        generate_report(session, console)

    elif choice == "0":
        show_settings(session, console)


def set_target(session: Session):
    """Prompt user to set/change target and auto-detect CMS."""
    console.print()
    raw = Prompt.ask("  [cyan]Enter target URL or domain[/cyan]", default=session.target or "")
    if not raw.strip():
        return

    target = raw.strip()
    if not target.startswith("http"):
        target = "https://" + target
    target = target.rstrip("/")
    session.target = target
    session.findings = []
    session.cms = None

    console.print(f"\n  [dim]Auto-detecting CMS for [cyan]{target}[/cyan]...[/dim]")
    cms = detect_cms(target, session.proxy)
    session.cms = cms

    if cms:
        console.print(f"  [bright_green]✓ CMS detected:[/bright_green] [bold]{cms}[/bold]")
    else:
        console.print("  [yellow]  CMS not identified — universal modules only[/yellow]")

    save_config(session)
    time.sleep(1.2)


def toggle_proxy(session: Session):
    """Toggle Burp proxy on/off."""
    console.print()
    if session.proxy:
        if Confirm.ask(f"  Proxy is [green]ON[/green] ({session.proxy}). Turn it off?"):
            session.proxy = None
            console.print("  [yellow]Proxy disabled.[/yellow]")
    else:
        host = Prompt.ask("  Proxy host", default="127.0.0.1")
        port = Prompt.ask("  Proxy port", default="8080")
        session.proxy = f"{host}:{port}"
        console.print(f"  [bright_green]✓ Proxy set to {session.proxy}[/bright_green]")
    save_config(session)
    time.sleep(1.0)


def main():
    parser = argparse.ArgumentParser(
        description="WebPwn Tools — Universal Web Penetration Testing Toolkit"
    )
    parser.add_argument("--target",  "-t", help="Target URL or domain")
    parser.add_argument("--proxy",   "-p", help="Proxy (host:port), e.g. 127.0.0.1:8080")
    parser.add_argument("--no-splash",     action="store_true", help="Skip splash screen")
    parser.add_argument("--module",  "-m", help="Run a specific module and exit (1-9)")
    parser.add_argument("--update",        action="store_true", help="Pull latest version from GitHub")
    args = parser.parse_args()
    
    if args.update:
        import subprocess, sys, os
        repo_dir = os.path.dirname(os.path.abspath(__file__))
        print("\n  Checking for updates...")
        subprocess.run(["git", "-C", repo_dir, "fetch", "origin"], capture_output=True, text=True)
        result = subprocess.run(["git", "-C", repo_dir, "reset", "--hard", "origin/master"], capture_output=True, text=True)
        if result.returncode == 0:
            print("  Update complete. Restarting...\n") if "HEAD" in result.stdout else print("  Already up to date.\n")
        else:
            print(f"  Update failed:\n  {result.stderr.strip()}\n")
        sys.exit(0)
    
    # Load saved config
    config = load_config()
    session = Session(config)

    # Override from CLI args
    if args.target:
        session.target = args.target
        if not session.target.startswith("http"):
            session.target = "https://" + session.target
    if args.proxy:
        session.proxy = args.proxy

    # Splash
    if not args.no_splash:
        splash_screen()

    # If a target was given via CLI, auto-detect CMS
    if session.target and not session.cms:
        console.print(f"  [dim]Detecting CMS for {session.target}...[/dim]")
        session.cms = detect_cms(session.target, session.proxy)

    # Non-interactive single-module mode
    if args.module:
        if not session.target:
            console.print("[bold red]Error: --target is required with --module[/bold red]")
            sys.exit(1)
        run_module(args.module, session)
        generate_report(session, console)
        sys.exit(0)

    # Interactive loop
    while True:
        print_main_menu(session)
        try:
            choice = Prompt.ask("  [bold bright_green]Select module[/bold bright_green]",
                                default="").strip().lower()
        except (KeyboardInterrupt, EOFError):
            console.print("\n\n  [dim]Goodbye.[/dim]\n")
            break

        if choice == "q":
            console.print("\n  [dim]Goodbye.[/dim]\n")
            break
        elif choice == "r":
            set_target(session)
        elif choice == "p":
            toggle_proxy(session)
        elif choice == "c":
            session.findings = []
            console.print("  [dim]Findings cleared.[/dim]")
            time.sleep(0.8)
        elif choice in [m[0] for m in MODULES]:
            run_module(choice, session)
        else:
            console.print("  [dim red]Invalid option.[/dim red]")
            time.sleep(0.6)


if __name__ == "__main__":
    main()
