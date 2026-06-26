"""
Module 3 — Directory & File Enumeration
Runs Gobuster with CMS-aware wordlists. Falls back to feroxbuster if gobuster absent.
"""
import subprocess
import os
from urllib.parse import urlparse
from rich.panel import Panel
from rich.table import Table
from rich.console import Console
from rich.prompt import Prompt, Confirm
from modules.session import Session

CMS_WORDLISTS = {
    "WordPress": [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt",
    ],
    "Joomla": [
        "/usr/share/seclists/Discovery/Web-Content/CMS/joomla.fuzz.txt",
        "/usr/share/wordlists/dirb/common.txt",
    ],
    "Drupal": [
        "/usr/share/seclists/Discovery/Web-Content/CMS/drupal.txt",
        "/usr/share/wordlists/dirb/common.txt",
    ],
    "default": [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
    ],
}

SENSITIVE_EXTENSIONS = "php,bak,old,txt,sql,zip,tar,gz,env,log,conf,config,yaml,yml,json"


def run_dir_enum(session: Session, console: Console):
    console.clear()
    console.print(Panel(
        f"[bold]Directory & File Enumeration[/bold]  →  [cyan]{session.target}[/cyan]",
        border_style="bright_blue"
    ))
    console.print()

    # Pick wordlist
    wordlist = _pick_wordlist(session, console)
    if not wordlist:
        console.print("  [red]  No valid wordlist found.[/red]")
        console.print("[dim]Press Enter to return...[/dim]")
        input()
        return

    console.print(f"  [dim]Wordlist: {wordlist}[/dim]")
    console.print(f"  [dim]Threads:  {session.threads}[/dim]")
    console.print()

    # Ask scan type
    console.print("  [bold]Scan type:[/bold]")
    console.print("  [1] Standard directory scan (fast)")
    console.print("  [2] Extended — include file extensions (slower)")
    console.print("  [3] Custom path prefix (e.g. /admin)")
    console.print()
    mode = Prompt.ask("  Choose", choices=["1","2","3"], default="1")

    _run_gobuster(session, console, wordlist, mode)

    console.print()
    console.print("[dim]Press Enter to return to menu...[/dim]")
    input()


def _pick_wordlist(session: Session, console: Console) -> str | None:
    cms = session.cms or "default"
    candidates = CMS_WORDLISTS.get(cms, CMS_WORDLISTS["default"])
    # Also try session wordlist
    candidates = [session.wordlist] + candidates

    for wl in candidates:
        if os.path.exists(wl):
            return wl

    # Last resort fallback — generate tiny inline wordlist
    fallback = "/tmp/webpwn_mini.txt"
    common = [
        "admin","login","wp-admin","administrator","backup","config",
        "uploads","images","js","css","api","test","dev","old","tmp",
        "wp-content","wp-includes","wp-login.php","xmlrpc.php",
        ".env",".git","robots.txt","sitemap.xml","crossdomain.xml",
        "phpinfo.php","info.php","server-status","server-info",
    ]
    with open(fallback, "w") as f:
        f.write("\n".join(common))
    console.print(f"  [yellow]  No system wordlist found — using built-in mini list ({len(common)} entries)[/yellow]")
    console.print("  [dim]  Install seclists: apt install seclists[/dim]")
    return fallback


def _run_gobuster(session: Session, console: Console, wordlist: str, mode: str):
    console.print("[bold cyan]  ── Gobuster ─────────────────────────────[/bold cyan]")

    proxy_flag = ["--proxy", f"http://{session.proxy}"] if session.proxy else []
    prefix = ""
    if mode == "3":
        prefix = Prompt.ask("  Path prefix", default="/")

    base_cmd = [
        "gobuster", "dir",
        "-u", session.target + prefix,
        "-w", wordlist,
        "-t", str(session.threads),
        "--no-progress",
        "-q",
    ] + proxy_flag

    if mode == "2":
        base_cmd += ["-x", SENSITIVE_EXTENSIONS]

    cmd_str = " ".join(base_cmd)
    console.print(f"  [dim]$ {cmd_str}[/dim]")
    console.print()

    found = []
    try:
        proc = subprocess.Popen(
            base_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue

            # Gobuster output: /path (Status: 200) [Size: 1234]
            status = ""
            if "Status: 200" in line or "(Status: 200)" in line:
                console.print(f"  [bright_green]{line}[/bright_green]")
                status = "200"
            elif any(s in line for s in ["Status: 30", "(Status: 30"]):
                console.print(f"  [cyan]{line}[/cyan]")
                status = "3xx"
            elif "Status: 403" in line or "(Status: 403)" in line:
                console.print(f"  [yellow]{line}[/yellow]")
                status = "403"
            else:
                console.print(f"  [dim]{line}[/dim]")

            found.append(line)

            # Flag interesting paths as findings
            path_lower = line.lower()
            for keyword in [".env", ".git", "backup", "config", "old", ".sql", ".log"]:
                if keyword in path_lower and status in ("200", "3xx"):
                    session.add_finding(
                        "HIGH",
                        f"Sensitive path discovered: {line.split()[0]}",
                        f"A potentially sensitive file or directory was found: {line}",
                        evidence=line,
                        remediation="Restrict access to this path or remove the file.",
                        module="Dir Enum"
                    )

        proc.wait()
        session.log_command(cmd_str, "\n".join(found[:100]))
        console.print(f"\n  [dim]Found {len(found)} entries.[/dim]")

    except FileNotFoundError:
        console.print("  [yellow]  gobuster not found.[/yellow]")
        console.print("  [dim]  Install: apt install gobuster  (pre-installed on Kali)[/dim]")
        _try_feroxbuster(session, console, wordlist, proxy_flag)
    except Exception as e:
        console.print(f"  [red]  Gobuster error: {e}[/red]")


def _try_feroxbuster(session: Session, console: Console, wordlist: str, proxy_flag: list):
    """Fallback to feroxbuster if gobuster is absent."""
    console.print("\n  [dim]Trying feroxbuster as fallback...[/dim]")
    cmd = [
        "feroxbuster",
        "--url", session.target,
        "--wordlist", wordlist,
        "--threads", str(session.threads),
        "--quiet",
        "--no-recursion",
    ] + (["--proxy", f"http://{session.proxy}"] if session.proxy else [])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        for line in result.stdout.splitlines():
            if line.strip():
                console.print(f"  {line}")
        session.log_command(" ".join(cmd), result.stdout[:1000])
    except FileNotFoundError:
        console.print("  [red]  feroxbuster also not found. Please install gobuster or feroxbuster.[/red]")
    except Exception as e:
        console.print(f"  [red]  feroxbuster error: {e}[/red]")
