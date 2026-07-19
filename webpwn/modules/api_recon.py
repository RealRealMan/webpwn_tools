"""Module 6 — API & JS Recon"""
import subprocess
import requests
import re
from rich.panel import Panel
from rich.console import Console
from rich.prompt import Prompt
from modules.session import Session

UA = "Mozilla/5.0 (compatible; WebPwnTools/2.0; security-assessment)"

# Fix #3: Tightened patterns — require actual quoted values of sufficient length
# Avoids matching JS variable names like 'forgotPasswordTPA', 'apply-session-token'
SECRET_PATTERNS = [
    # API keys — must have quoted value 20+ chars
    (r'(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "API Key"),
    # Secrets/tokens/passwords — must be quoted + 16+ alphanumeric chars (not just a word)
    (r'(?i)(?:secret|password|passwd)\s*[:=]\s*["\']([A-Za-z0-9_\-\/\+]{16,})["\']', "Secret/Password"),
    # Bearer tokens — long enough to be real
    (r'(?i)bearer\s+([A-Za-z0-9\-_\.]{40,})', "Bearer Token"),
    # AWS keys — specific format
    (r'(?:AKIA|ASIA|AROA)[0-9A-Z]{16}', "AWS Access Key"),
    # Google API keys — specific prefix
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key"),
    # Private keys
    (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', "Private Key"),
    # Hardcoded passwords in assignment
    (r'(?i)(?:password|passwd|pwd)\s*=\s*["\']([^"\']{8,})["\']', "Hardcoded Password"),
]

# Known false-positive patterns to skip
FP_PATTERNS = [
    r'forgotPassword', r'resetPassword', r'changePassword',
    r'apply-session', r'session-token', r'token-expire',
    r'getToken', r'setToken', r'parseToken', r'tokenType',
    r'members-reset', r'forgot.*tpa', r'password.*placeholder',
]


def run_api_recon(session: Session, console: Console):
    console.clear()
    console.print(Panel(
        f"[bold]API & JS Recon[/bold]  →  [cyan]{session.target}[/cyan]",
        border_style="bright_blue"
    ))
    console.print()

    _crawl_js_files(session, console)
    _check_common_api_endpoints(session, console)

    console.print()
    console.print("[dim]Press Enter to return to menu...[/dim]")
    input()


def _is_false_positive(value: str) -> bool:
    """Check if a matched value looks like a false positive."""
    for pattern in FP_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            return True
    # If value looks like a variable name (camelCase, kebab-case with no real entropy)
    # Real secrets are usually random-looking, not readable words
    if re.match(r'^[a-z]+(?:[A-Z][a-z]+)*$', value) and len(value) < 30:
        return True
    return False


def _crawl_js_files(session: Session, console: Console):
    console.print("[bold cyan]  ── JS File Secrets Scan ──────────────────[/bold cyan]")
    proxies = session.proxy_dict()
    try:
        r = requests.get(session.target, headers={"User-Agent": UA},
                         proxies=proxies, timeout=10, verify=False)
        js_urls = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', r.text)
        console.print(f"  [dim]Found {len(js_urls)} JS files[/dim]")

        total_found = 0
        for js_url in js_urls[:10]:
            if not js_url.startswith("http"):
                js_url = session.target.rstrip("/") + "/" + js_url.lstrip("/")
            try:
                jr = requests.get(js_url, headers={"User-Agent": UA},
                                  proxies=proxies, timeout=8, verify=False)
                for pattern, label in SECRET_PATTERNS:
                    matches = re.findall(pattern, jr.text)
                    for m in matches[:3]:
                        val = m if isinstance(m, str) else (m[-1] if m else "")
                        if not val or _is_false_positive(val):
                            continue
                        console.print(f"  [bold red]✗ {label} in {js_url.split('/')[-1]}: {val[:40]}[/bold red]")
                        session.add_finding(
                            "HIGH", f"{label} exposed in JS file",
                            f"Found in {js_url}",
                            evidence=f"{label}: {val[:60]}",
                            remediation="Remove secrets from client-side code. Use server-side environment variables.",
                            module="API Recon"
                        )
                        total_found += 1
            except Exception:
                pass

        if total_found == 0:
            console.print("  [green]  No secrets detected in JS files.[/green]")

    except Exception as e:
        console.print(f"  [red]  Error: {e}[/red]")
    console.print()


def _check_common_api_endpoints(session: Session, console: Console):
    console.print("[bold cyan]  ── Common API Endpoint Discovery ──────────[/bold cyan]")
    endpoints = [
        "/api", "/api/v1", "/api/v2", "/graphql", "/swagger",
        "/swagger.json", "/openapi.json", "/api-docs", "/.well-known/",
        "/rest/v1", "/wp-json/", "/wp-json/wp/v2/users",
    ]
    proxies = session.proxy_dict()
    for ep in endpoints:
        url = session.target + ep
        try:
            r = requests.get(url, headers={"User-Agent": UA},
                             proxies=proxies, timeout=5,
                             verify=False, allow_redirects=False)
            if r.status_code == 200:
                console.print(f"  [bright_green]200[/bright_green]  {url}")
                if "users" in ep:
                    session.add_finding(
                        "HIGH", f"User data exposed at {ep}",
                        "API endpoint returns user information without authentication.",
                        evidence=url,
                        remediation="Restrict or authenticate this endpoint.",
                        module="API Recon"
                    )
            elif r.status_code in (301, 302, 403):
                console.print(f"  [yellow]{r.status_code}[/yellow]  {url}")
        except Exception:
            pass
    console.print()
