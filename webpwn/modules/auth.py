"""
Module 5 — Authentication Testing
Tests login error message disclosure, rate limiting, and session security.
"""
import requests
import subprocess
from rich.panel import Panel
from rich.console import Console
from rich.prompt import Prompt, Confirm
from modules.session import Session

UA = "Mozilla/5.0 (compatible; WebPwnTools/2.0; security-assessment)"


def run_auth(session: Session, console: Console):
    console.clear()
    console.print(Panel(
        f"[bold]Auth Testing[/bold]  →  [cyan]{session.target}[/cyan]",
        border_style="bright_blue"
    ))
    console.print()
    console.print("  [bold]Select test:[/bold]")
    console.print("  [1] Login page discovery")
    console.print("  [2] Error message disclosure (username enumeration via login)")
    console.print("  [3] Rate limit check (does login throttle on bad attempts?)")
    console.print("  [4] Brute-force with Hydra (requires wordlists)")
    console.print("  [b] Back")
    console.print()
    choice = Prompt.ask("  Choose", default="b").strip().lower()

    if choice == "1":   _find_login_pages(session, console)
    elif choice == "2": _check_error_disclosure(session, console)
    elif choice == "3": _check_rate_limit(session, console)
    elif choice == "4": _run_hydra(session, console)

    console.print()
    console.print("[dim]Press Enter to return to menu...[/dim]")
    input()


def _find_login_pages(session: Session, console: Console):
    console.print("[bold cyan]  ── Login Page Discovery ──────────────────[/bold cyan]")
    paths = [
        "/login", "/signin", "/admin", "/admin/login", "/user/login",
        "/wp-login.php", "/wp-admin/", "/administrator/", "/user/login",
        "/account/login", "/auth/login", "/portal/login", "/panel",
    ]
    proxies = session.proxy_dict()
    found = []
    for path in paths:
        url = session.target + path
        try:
            r = requests.get(url, headers={"User-Agent": UA},
                             proxies=proxies, timeout=6, verify=False, allow_redirects=False)
            if r.status_code in (200, 301, 302, 403):
                color = "bright_green" if r.status_code == 200 else "yellow"
                console.print(f"  [{color}]{r.status_code}[/{color}]  {url}")
                found.append(url)
        except Exception:
            pass

    if not found:
        console.print("  [dim]  No standard login pages found.[/dim]")
    else:
        for u in found:
            session.add_finding("INFO", f"Login page found: {u}", "",
                                evidence=u, module="Auth")
    console.print()


def _check_error_disclosure(session: Session, console: Console):
    console.print("[bold cyan]  ── Login Error Message Disclosure ─────────[/bold cyan]")
    login_url = Prompt.ask("  Login URL", default=session.target + "/wp-login.php")
    proxies = session.proxy_dict()
    tests = [
        ("valid_user_wrong_pass", {"log": "admin", "pwd": "WRONG_PASS_xyz123!"}),
        ("invalid_user",          {"log": "notarealuser_xyz999", "pwd": "test"}),
    ]
    responses = {}
    for label, data in tests:
        try:
            r = requests.post(login_url, data=data,
                              headers={"User-Agent": UA},
                              proxies=proxies, timeout=8, verify=False)
            responses[label] = r.text.lower()
            snippet = r.text[:200].replace("\n", " ").strip()
            console.print(f"  [dim]{label}:[/dim] {snippet[:120]}...")
        except Exception as e:
            console.print(f"  [red]  Error: {e}[/red]")

    if len(responses) == 2:
        if responses["valid_user_wrong_pass"] != responses["invalid_user"]:
            console.print("\n  [bold red]✗ Different error messages for valid vs invalid username![/bold red]")
            console.print("  [red]  This allows username enumeration via login page.[/red]")
            session.add_finding(
                "MEDIUM", "Username enumeration via login error messages",
                "The login page returns different responses for valid vs invalid usernames.",
                evidence="Different HTTP response body/status for valid user vs unknown user",
                remediation="Use a generic error message: 'Invalid username or password' for all failures.",
                module="Auth"
            )
        else:
            console.print("\n  [green]  Error messages appear consistent — no obvious enumeration.[/green]")
    console.print()


def _check_rate_limit(session: Session, console: Console):
    console.print("[bold cyan]  ── Rate Limit Check ──────────────────────[/bold cyan]")
    login_url = Prompt.ask("  Login URL", default=session.target + "/wp-login.php")
    proxies = session.proxy_dict()
    console.print("  [dim]Sending 10 rapid login attempts...[/dim]")

    statuses = []
    for i in range(10):
        try:
            r = requests.post(login_url,
                              data={"log": "admin", "pwd": f"wrongpass{i}"},
                              headers={"User-Agent": UA},
                              proxies=proxies, timeout=6, verify=False)
            statuses.append(r.status_code)
            console.print(f"  [dim]  Attempt {i+1}: {r.status_code}[/dim]")
        except Exception as e:
            statuses.append(0)
            console.print(f"  [dim]  Attempt {i+1}: error ({e})[/dim]")

    if any(s in (429, 503) for s in statuses):
        console.print("\n  [green]  Rate limiting detected (429/503 response).[/green]")
    elif all(s == 200 for s in statuses):
        console.print("\n  [bold red]✗ No rate limiting detected — all 10 attempts returned 200.[/bold red]")
        session.add_finding(
            "HIGH", "No login rate limiting",
            "The login endpoint does not throttle repeated failed attempts, enabling brute-force.",
            evidence="10 consecutive failed login attempts returned HTTP 200",
            remediation="Implement rate limiting (e.g. fail2ban, Wordfence, Cloudflare). Lock account after N failures.",
            module="Auth"
        )
    console.print()


def _run_hydra(session: Session, console: Console):
    console.print("[bold cyan]  ── Hydra Brute-Force ─────────────────────[/bold cyan]")
    console.print("  [bold yellow]⚠  Only run against systems you own or have explicit written permission.[/bold yellow]")
    console.print()
    if not Confirm.ask("  Confirm authorization to brute-force this target"):
        console.print("  [dim]Cancelled.[/dim]")
        return

    login_url  = Prompt.ask("  Login URL", default=session.target + "/wp-login.php")
    post_data  = Prompt.ask("  POST data (use ^USER^ and ^PASS^)",
                             default="log=^USER^&pwd=^PASS^&wp-submit=Log+In")
    fail_str   = Prompt.ask("  Failure string in response", default="Incorrect password")
    userlist   = Prompt.ask("  Username list", default="/usr/share/wordlists/metasploit/namelist.txt")
    passlist   = Prompt.ask("  Password list", default="/usr/share/wordlists/rockyou.txt")

    cmd = [
        "hydra", "-L", userlist, "-P", passlist,
        "-s", "443", "-S",
        login_url.replace("https://", "").replace("http://", "").split("/")[0],
        "https-post-form",
        f"{login_url.split(login_url.split('/')[2])[-1]}:{post_data}:F={fail_str}",
        "-t", "4", "-w", "10",
    ]

    console.print(f"  [dim]$ {' '.join(cmd)}[/dim]")
    console.print()

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in proc.stdout:
            line = line.strip()
            if "login:" in line.lower():
                console.print(f"  [bold red]✗ CREDENTIAL FOUND: {line}[/bold red]")
                session.add_finding("CRITICAL", "Credential found via brute-force",
                                    line, evidence=line, module="Auth")
            elif line:
                console.print(f"  [dim]{line}[/dim]")
        proc.wait()
    except FileNotFoundError:
        console.print("  [yellow]  hydra not found. Install: apt install hydra[/yellow]")
    except Exception as e:
        console.print(f"  [red]  Hydra error: {e}[/red]")
    console.print()
