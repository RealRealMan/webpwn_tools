"""
Settings — load/save config.yaml and display settings screen.
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
    }
    with open(CONFIG_PATH, "w") as f:
        yaml.dump(data, f, default_flow_style=False)


def show_settings(session, console: Console):
    console.clear()
    console.print(Panel("[bold bright_blue]Settings[/bold bright_blue]",
                        border_style="bright_blue"))
    console.print()

    # Current config table
    t = Table(show_header=True, header_style="bold cyan",
              border_style="dim", show_lines=True)
    t.add_column("Setting",   style="bold white", width=18)
    t.add_column("Value",     style="cyan")
    t.add_column("Notes",     style="dim")

    proxy_val = f"[green]{session.proxy}[/green]" if session.proxy else "[dim red]disabled[/dim red]"
    wpscan_val = "[green]set[/green]" if session.wpscan_api else "[dim red]not set[/dim red]"

    t.add_row("target",     session.target or "[dim]not set[/dim]",    "URL or domain")
    t.add_row("proxy",      proxy_val,                                  "Burp: 127.0.0.1:8080")
    t.add_row("cms",        session.cms or "[dim]auto-detect[/dim]",   "Set automatically on target change")
    t.add_row("threads",    str(session.threads),                       "Concurrent threads")
    t.add_row("rate_limit", f"{session.rate_limit} req/s",             "Max requests per second")
    t.add_row("wpscan_api", wpscan_val,                                 "From wpscan.com (free)")
    t.add_row("report_dir", session.report_dir,                        "HTML report output path")
    t.add_row("wordlist",   session.wordlist,                           "Dir enum wordlist path")

    console.print(t)
    console.print()

    # Proxy help
    console.print("[bold]Burp Suite proxy setup:[/bold]")
    console.print("[dim]  1. Open Burp → Proxy → Options → ensure listener on 127.0.0.1:8080[/dim]")
    console.print("[dim]  2. For HTTPS: Proxy → CA Certificate → export and trust in system/browser[/dim]")
    console.print("[dim]  3. Enable proxy here — all tool requests will route through Burp[/dim]")
    console.print()

    console.print("[bold]Edit settings:[/bold]  [dim]e=edit  b=back[/dim]")
    choice = Prompt.ask("  Option", default="b").strip().lower()

    if choice == "e":
        _edit_settings(session, console)
        save_config(session)


def _edit_settings(session, console: Console):
    console.print()
    fields = [
        ("threads",     "Threads",           str(session.threads)),
        ("rate_limit",  "Rate limit (req/s)",str(session.rate_limit)),
        ("wpscan_api",  "WPScan API token",  session.wpscan_api),
        ("report_dir",  "Report directory",  session.report_dir),
        ("wordlist",    "Wordlist path",      session.wordlist),
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

    # Proxy toggle
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
