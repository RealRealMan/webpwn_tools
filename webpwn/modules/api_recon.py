"""Module 6 — API & JS Recon"""
import subprocess, requests, re
from rich.panel import Panel
from rich.console import Console
from rich.prompt import Prompt
from modules.session import Session

UA = "Mozilla/5.0 (compatible; WebPwnTools/2.0; security-assessment)"
SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})', "API Key"),
    (r'(?i)(secret|token|password|passwd|pwd)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{8,})', "Secret/Token"),
    (r'(?i)(aws_access_key_id)\s*[:=]\s*([A-Z0-9]{20})', "AWS Key"),
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key"),
    (r'(?i)bearer\s+([A-Za-z0-9\-_\.]{20,})', "Bearer Token"),
]


def run_api_recon(session: Session, console: Console):
    console.clear()
    console.print(Panel(f"[bold]API & JS Recon[/bold]  →  [cyan]{session.target}[/cyan]", border_style="bright_blue"))
    console.print()

    _crawl_js_files(session, console)
    _check_common_api_endpoints(session, console)

    console.print()
    console.print("[dim]Press Enter to return to menu...[/dim]")
    input()


def _crawl_js_files(session: Session, console: Console):
    console.print("[bold cyan]  ── JS File Secrets Scan ──────────────────[/bold cyan]")
    proxies = session.proxy_dict()
    try:
        r = requests.get(session.target, headers={"User-Agent": UA},
                         proxies=proxies, timeout=10, verify=False)
        js_urls = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', r.text)
        console.print(f"  [dim]Found {len(js_urls)} JS files[/dim]")
        for js_url in js_urls[:10]:
            if not js_url.startswith("http"):
                js_url = session.target.rstrip("/") + "/" + js_url.lstrip("/")
            try:
                jr = requests.get(js_url, headers={"User-Agent": UA},
                                  proxies=proxies, timeout=8, verify=False)
                for pattern, label in SECRET_PATTERNS:
                    matches = re.findall(pattern, jr.text)
                    for m in matches[:3]:
                        val = m if isinstance(m, str) else m[-1]
                        console.print(f"  [bold red]✗ {label} in {js_url.split('/')[-1]}: {val[:40]}...[/bold red]")
                        session.add_finding("HIGH", f"Potential {label} exposed in JS",
                                            f"Found in {js_url}", evidence=f"{label}: {val[:60]}",
                                            remediation="Remove secrets from client-side code. Use server-side env vars.",
                                            module="API Recon")
            except Exception:
                pass
    except Exception as e:
        console.print(f"  [red]  Error: {e}[/red]")
    console.print()


def _check_common_api_endpoints(session: Session, console: Console):
    console.print("[bold cyan]  ── Common API Endpoint Discovery ──────────[/bold cyan]")
    endpoints = [
        "/api", "/api/v1", "/api/v2", "/graphql", "/swagger", "/swagger.json",
        "/openapi.json", "/api-docs", "/.well-known/", "/rest/v1",
        "/wp-json/", "/wp-json/wp/v2/users",
    ]
    proxies = session.proxy_dict()
    for ep in endpoints:
        url = session.target + ep
        try:
            r = requests.get(url, headers={"User-Agent": UA},
                             proxies=proxies, timeout=5, verify=False, allow_redirects=False)
            if r.status_code == 200:
                console.print(f"  [bright_green]200[/bright_green]  {url}")
                if "users" in ep and r.status_code == 200:
                    session.add_finding("HIGH", f"User data exposed at {ep}",
                                        "API endpoint returns user information without authentication.",
                                        evidence=url, remediation="Restrict or authenticate this endpoint.",
                                        module="API Recon")
            elif r.status_code in (301, 302, 403):
                console.print(f"  [yellow]{r.status_code}[/yellow]  {url}")
        except Exception:
            pass
    console.print()
