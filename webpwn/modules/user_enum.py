"""Module 8 — User Enumeration (CMS-aware)"""
import requests
from rich.panel import Panel
from rich.console import Console
from modules.session import Session

UA = "Mozilla/5.0 (compatible; WebPwnTools/2.0; security-assessment)"


def run_user_enum(session: Session, console: Console):
    console.clear()
    console.print(Panel(
        f"[bold]User Enumeration[/bold]  →  [cyan]{session.target}[/cyan]  [dim]CMS: {session.cms or 'unknown'}[/dim]",
        border_style="bright_blue"
    ))
    console.print()

    proxies = session.proxy_dict()

    if session.cms == "WordPress":
        _enum_wordpress(session, console, proxies)
    elif session.cms == "Joomla":
        _enum_joomla(session, console, proxies)
    elif session.cms == "Drupal":
        _enum_drupal(session, console, proxies)
    else:
        console.print("  [dim]No CMS detected — running generic author param test.[/dim]")
        _enum_generic(session, console, proxies)

    console.print()
    console.print("[dim]Press Enter to return to menu...[/dim]")
    input()


def _enum_wordpress(session: Session, console: Console, proxies):
    console.print("[bold cyan]  ── WordPress User Enumeration ────────────[/bold cyan]")

    # REST API
    api_url = session.target + "/wp-json/wp/v2/users"
    try:
        r = requests.get(api_url, headers={"User-Agent": UA},
                         proxies=proxies, timeout=10, verify=False)
        if r.status_code == 200:
            users = r.json() if r.headers.get("content-type","").startswith("application/json") else []
            if isinstance(users, list) and users:
                console.print(f"  [bold red]✗ REST API exposes {len(users)} user(s):[/bold red]")
                for u in users:
                    console.print(f"  [red]  id={u.get('id')}  name={u.get('name')}  slug={u.get('slug')}[/red]")
                session.add_finding("HIGH", "WordPress REST API exposes user list",
                                    f"/wp-json/wp/v2/users returned {len(users)} users publicly.",
                                    evidence=api_url, remediation="Restrict the users endpoint in functions.php or via a security plugin.",
                                    module="User Enum")
            else:
                console.print(f"  [green]  REST API users endpoint returned {r.status_code} / no user data.[/green]")
        else:
            console.print(f"  [green]  REST API users endpoint: {r.status_code} (protected)[/green]")
    except Exception as e:
        console.print(f"  [dim]  REST API error: {e}[/dim]")

    # Author archive enumeration
    console.print()
    console.print("  [dim]Testing ?author= parameter...[/dim]")
    for i in range(1, 6):
        url = f"{session.target}/?author={i}"
        try:
            r = requests.get(url, headers={"User-Agent": UA},
                             proxies=proxies, timeout=6, verify=False, allow_redirects=True)
            if r.status_code == 200 and "/author/" in r.url:
                username = r.url.split("/author/")[-1].strip("/")
                console.print(f"  [bold red]✗ User #{i}: [/bold red][red]{username}[/red] (via ?author={i})")
                session.add_finding("MEDIUM", f"WordPress user enumerable via ?author={i}",
                                    f"Username '{username}' discovered via author redirect.",
                                    evidence=f"GET /?author={i} → {r.url}",
                                    remediation="Block ?author= requests in .htaccess to prevent enumeration.",
                                    module="User Enum")
            else:
                console.print(f"  [dim]  ?author={i} → {r.status_code}[/dim]")
        except Exception:
            pass
    console.print()


def _enum_joomla(session: Session, console: Console, proxies):
    console.print("[bold cyan]  ── Joomla User Enumeration ───────────────[/bold cyan]")
    paths = ["/index.php?option=com_users&view=registration", "/administrator/"]
    for path in paths:
        url = session.target + path
        try:
            r = requests.get(url, headers={"User-Agent": UA},
                             proxies=proxies, timeout=8, verify=False)
            console.print(f"  {r.status_code}  {url}")
        except Exception as e:
            console.print(f"  [dim]  {url} — {e}[/dim]")
    console.print()


def _enum_drupal(session: Session, console: Console, proxies):
    console.print("[bold cyan]  ── Drupal User Enumeration ───────────────[/bold cyan]")
    for uid in range(1, 5):
        url = f"{session.target}/user/{uid}"
        try:
            r = requests.get(url, headers={"User-Agent": UA},
                             proxies=proxies, timeout=6, verify=False, allow_redirects=True)
            if r.status_code == 200 and "/user/" in r.url:
                console.print(f"  [bright_green]User #{uid} exists:[/bright_green] {r.url}")
            else:
                console.print(f"  [dim]  /user/{uid} → {r.status_code}[/dim]")
        except Exception:
            pass
    console.print()


def _enum_generic(session: Session, console: Console, proxies):
    paths = ["/?author=1", "/user/1", "/profile/admin", "/users/admin"]
    for path in paths:
        url = session.target + path
        try:
            r = requests.get(url, headers={"User-Agent": UA},
                             proxies=proxies, timeout=6, verify=False, allow_redirects=False)
            console.print(f"  {r.status_code}  {url}")
        except Exception:
            pass
    console.print()
