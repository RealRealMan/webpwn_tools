"""
Settings — load/save config.yaml, engagement info, display settings screen.
Fix #10: Engagement fields with placeholder hints.
"""
import os
import yaml
from pathlib import Path
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.console import Console

CONFIG_PATH = Path.home() / ".config" / "webpwn" / "config.yaml"

DEFAULTS = {
    "target":      "",
    "proxy":       None,
    "cms":         None,
    "threads":     10,
    "rate_limit":  50,
    "wpscan_api":  "",
    "report_dir":  str(Path.home() / "webpwn" / "reports"),
    "wordlist":    "/usr/share/wordlists/dirb/common.txt",
    # Engagement info
    "assessor":    "",
    "client":      "",
    "test_start":  "",
    "test_end":    "",
    "auth_ref":    "",
    "in_scope":    "",
    "out_scope":   "",
    "test_type":   "Black-box Web Application Pentest",
}


def load_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH) as f:
                data = yaml.safe_load(f) or {}
            merged = DEFAULTS.copy()
            merged.update(data)
            return merged
        except Exception:
            pass
    return DEFAULTS.copy()


def save_config(session):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "target":     session.target,
        "proxy":      session.proxy,
        "cms":        session.cms,
        "threads":    session.threads,
        "rate_limit": session.rate_limit,
        "wpscan_api": session.wpscan_api,
        "report_dir": session.report_dir,
        "wordlist":   session.wordlist,
        "assessor":   session.assessor,
        "client":     session.client,
        "test_start": session.test_start,
        "test_end":   session.test_end,
        "auth_ref":   session.auth_ref,
        "in_scope":   session.in_scope,
        "out_scope":  session.out_scope,
        "test_type":  session.test_type,
    }
    with open(CONFIG_PATH, "w") as f:
        yaml.dump(data, f, default_flow_style=False)


def show_settings(session, console: Console):
    console.clear()
    console.print(Panel("[bold bright_blue]Settings[/bold bright_blue]",
                        border_style="bright_blue"))
    console.print()

    # Tool config table
    console.print("  [bold cyan]── Tool Configuration ──────────────────────────────[/bold cyan]")
    t = Table(show_header=True, header_style="bold cyan",
              border_style="dim", show_lines=True)
    t.add_column("Setting",  style="bold white", width=18)
    t.add_column("Value",    style="cyan")
    t.add_column("Notes",    style="dim")

    proxy_val   = f"[green]{session.proxy}[/green]" if session.proxy else "[dim red]disabled[/dim red]"
    wpscan_val  = "[green]set[/green]" if session.wpscan_api else "[dim red]not set[/dim red]"

    t.add_row("target",     session.target or "[dim]not set[/dim]",   "URL or domain")
    t.add_row("proxy",      proxy_val,                                 "Burp: 127.0.0.1:8080")
    t.add_row("threads",    str(session.threads),                      "Concurrent threads")
    t.add_row("rate_limit", f"{session.rate_limit} req/s",            "Max requests per second")
    t.add_row("wpscan_api", wpscan_val,                                "From wpscan.com (free)")
    t.add_row("report_dir", session.report_dir,                        "HTML report output")
    t.add_row("wordlist",   session.wordlist,                          "Dir enum wordlist")
    console.print(t)
    console.print()

    # Engagement info table
    console.print("  [bold cyan]── Engagement Information (for report) ─────────────[/bold cyan]")
    e = Table(show_header=True, header_style="bold cyan",
              border_style="dim", show_lines=True)
    e.add_column("Field",       style="bold white", width=22)
    e.add_column("Value",       style="cyan")
    e.add_column("Placeholder", style="dim")

    # Fix #10: show placeholder hints
    eng_fields = [
        ("assessor",   "Assessor / Tester",       session.assessor,   "e.g. Jane Smith"),
        ("client",     "Client / Organisation",   session.client,     "e.g. Acme Corp"),
        ("test_start", "Test Start Date",          session.test_start, "e.g. 2026-07-01"),
        ("test_end",   "Test End Date",            session.test_end,   "e.g. 2026-07-07"),
        ("auth_ref",   "Authorisation Reference",  session.auth_ref,   "e.g. Email from CEO dated 2026-06-30"),
        ("in_scope",   "In-Scope",                session.in_scope,   "e.g. https://target.com and all subpages"),
        ("out_scope",  "Out-of-Scope",            session.out_scope,  "e.g. Payment gateway, third-party APIs"),
        ("test_type",  "Testing Type",             session.test_type,  "e.g. Black-box / Grey-box"),
    ]
    for _, label, val, hint in eng_fields:
        display = val if val else "[dim]not set[/dim]"
        e.add_row(label, display, hint)
    console.print(e)
    console.print()

    # Burp help
    console.print("  [bold]Burp Suite proxy:[/bold]")
    console.print("  [dim]  1. Burp → Proxy → Options → listener on 127.0.0.1:8080[/dim]")
    console.print("  [dim]  2. For HTTPS: export Burp CA cert and trust in system[/dim]")
    console.print("  [dim]  3. Enable proxy here — all requests route through Burp[/dim]")
    console.print()
    console.print("  [bold]Options:[/bold]  [dim]e=edit tool config  g=edit engagement info  b=back[/dim]")

    choice = Prompt.ask("  Option", default="b").strip().lower()
    if choice == "e":
        _edit_tool_config(session, console)
        save_config(session)
    elif choice == "g":
        _edit_engagement(session, console)
        save_config(session)


def _edit_tool_config(session, console: Console):
    console.print()
    fields = [
        ("threads",    "Threads",            str(session.threads)),
        ("rate_limit", "Rate limit (req/s)", str(session.rate_limit)),
        ("wpscan_api", "WPScan API token",   session.wpscan_api),
        ("report_dir", "Report directory",   session.report_dir),
        ("wordlist",   "Wordlist path",      session.wordlist),
    ]
    for attr, label, current in fields:
        val = Prompt.ask(f"  [cyan]{label}[/cyan]", default=current)
        if attr in ("threads", "rate_limit"):
            try:
                setattr(session, attr, int(val))
            except ValueError:
                pass
        else:
            setattr(session, attr, val)

    console.print()
    if session.proxy:
        if Confirm.ask(f"  Proxy currently [green]{session.proxy}[/green]. Disable?"):
            session.proxy = None
    else:
        if Confirm.ask("  Enable Burp proxy?"):
            host = Prompt.ask("  Host", default="127.0.0.1")
            port = Prompt.ask("  Port", default="8080")
            session.proxy = f"{host}:{port}"

    console.print("[bright_green]  ✓ Settings saved.[/bright_green]")


def _edit_engagement(session, console: Console):
    """Fix #10: Edit engagement fields with clear placeholder guidance."""
    console.print()
    console.print("  [dim]Fill in engagement details for the report. Press Enter to keep current value.[/dim]")
    console.print()

    fields = [
        ("assessor",   "Assessor / Tester",       session.assessor,   "e.g. Jane Smith"),
        ("client",     "Client / Organisation",   session.client,     "e.g. Acme Corp"),
        ("test_start", "Test Start Date",          session.test_start, "e.g. 2026-07-01"),
        ("test_end",   "Test End Date",            session.test_end,   "e.g. 2026-07-07"),
        ("auth_ref",   "Authorisation Reference",  session.auth_ref,   "e.g. Email from CEO dated 2026-06-30"),
        ("in_scope",   "In-Scope",                session.in_scope,   "e.g. https://target.com and all subpages"),
        ("out_scope",  "Out-of-Scope",            session.out_scope,  "e.g. Payment gateway, third-party APIs"),
        ("test_type",  "Testing Type",             session.test_type,  "e.g. Black-box / Grey-box"),
    ]

    for attr, label, current, hint in fields:
        console.print(f"  [dim]{hint}[/dim]")
        val = Prompt.ask(f"  [cyan]{label}[/cyan]", default=current or "")
        setattr(session, attr, val.strip())

    console.print("\n  [bright_green]✓ Engagement info saved.[/bright_green]")
