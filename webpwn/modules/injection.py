"""
Module 4 — Injection Testing
Covers: XSS (dalfox), SQLi (sqlmap), SSTI, open redirect, CSRF checks.
"""
import subprocess
from rich.panel import Panel
from rich.console import Console
from rich.prompt import Prompt, Confirm
from modules.session import Session

UA = "Mozilla/5.0 (compatible; WebPwnTools/2.0; security-assessment)"


def run_injection(session: Session, console: Console):
    console.clear()
    console.print(Panel(
        f"[bold]Injection Tests[/bold]  →  [cyan]{session.target}[/cyan]",
        border_style="bright_blue"
    ))
    console.print()

    console.print("  [bold yellow]⚠  Active testing — ensure written authorization before proceeding.[/bold yellow]")
    console.print()
    console.print("  [bold]Select test:[/bold]")
    console.print("  [1] XSS scan (dalfox — crawl & parameter fuzz)")
    console.print("  [2] SQL injection (sqlmap — GET/POST parameter test)")
    console.print("  [3] SSTI detection (template injection payloads)")
    console.print("  [4] Open redirect check")
    console.print("  [5] CSRF header analysis")
    console.print("  [a] Run all")
    console.print("  [b] Back")
    console.print()

    choice = Prompt.ask("  Choose", default="b").strip().lower()

    runners = {
        "1": _run_xss,
        "2": _run_sqli,
        "3": _run_ssti,
        "4": _run_open_redirect,
        "5": _run_csrf_check,
    }

    if choice == "a":
        for fn in runners.values():
            fn(session, console)
    elif choice in runners:
        runners[choice](session, console)
    else:
        return

    console.print()
    console.print("[dim]Press Enter to return to menu...[/dim]")
    input()


def _run_xss(session: Session, console: Console):
    console.print("[bold cyan]  ── XSS Scan (dalfox) ─────────────────────[/bold cyan]")
    proxy_flags = ["--proxy", f"http://{session.proxy}"] if session.proxy else []

    cmd = [
        "dalfox", "url", session.target,
        "--silence",
        "--no-color",
        "--timeout", "30",
        "--worker", "10",
    ] + proxy_flags

    console.print(f"  [dim]$ {' '.join(cmd)}[/dim]")
    console.print()

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = result.stdout + result.stderr

        found = False
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            if "[POC]" in line or "VULN" in line.upper():
                console.print(f"  [bold red]✗ {line}[/bold red]")
                session.add_finding(
                    "HIGH", "XSS vulnerability detected",
                    "dalfox confirmed a reflected/stored XSS vector.",
                    evidence=line,
                    remediation="Sanitize and encode all user-controlled output. Implement a strict CSP.",
                    module="Injection"
                )
                found = True
            elif "[I]" in line or "[W]" in line:
                console.print(f"  [dim]{line}[/dim]")

        if not found:
            console.print("  [green]  No XSS found in this scan.[/green]")

        session.log_command(" ".join(cmd), output[:1000])

    except FileNotFoundError:
        console.print("  [yellow]  dalfox not found.[/yellow]")
        console.print("  [dim]  Install: go install github.com/hahwul/dalfox/v2@latest[/dim]")
        console.print("  [dim]  Or: apt install dalfox (Kali)[/dim]")
    except subprocess.TimeoutExpired:
        console.print("  [yellow]  dalfox timed out. Try with a specific URL: dalfox url 'URL?param=test'[/yellow]")
    except Exception as e:
        console.print(f"  [red]  dalfox error: {e}[/red]")

    console.print()


def _run_sqli(session: Session, console: Console):
    console.print("[bold cyan]  ── SQL Injection (sqlmap) ─────────────────[/bold cyan]")

    url = Prompt.ask(
        "  Target URL with parameter (e.g. https://site.com/page?id=1)",
        default=session.target + "?id=1"
    )

    proxy_flags = ["--proxy", f"http://{session.proxy}"] if session.proxy else []
    cmd = [
        "sqlmap", "-u", url,
        "--batch",
        "--level", "2",
        "--risk", "1",
        "--timeout", "10",
        "--output-dir", session.report_dir,
        "--user-agent", UA,
    ] + proxy_flags

    console.print(f"  [dim]$ {' '.join(cmd)}[/dim]")
    console.print()
    console.print("  [dim](This may take a few minutes...)[/dim]")
    console.print()

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout

        vuln_found = False
        for line in output.splitlines():
            line_s = line.strip()
            if not line_s:
                continue
            if "is vulnerable" in line_s.lower() or "[CRITICAL]" in line_s:
                console.print(f"  [bold red]{line_s}[/bold red]")
                session.add_finding(
                    "CRITICAL", "SQL injection vulnerability confirmed",
                    f"sqlmap confirmed SQL injection at: {url}",
                    evidence=line_s,
                    remediation="Use parameterized queries / prepared statements. Never interpolate user input into SQL.",
                    module="Injection"
                )
                vuln_found = True
            elif "[WARNING]" in line_s or "[INFO]" in line_s:
                console.print(f"  [dim]{line_s}[/dim]")
            elif "[PAYLOAD]" in line_s:
                console.print(f"  [yellow]{line_s}[/yellow]")

        if not vuln_found:
            console.print("  [green]  No SQL injection found at basic level.[/green]")
            console.print("  [dim]  Try with --level 3 --risk 2 for deeper testing.[/dim]")

        session.log_command(" ".join(cmd), output[:1000])

    except FileNotFoundError:
        console.print("  [yellow]  sqlmap not found.[/yellow]")
        console.print("  [dim]  Install: apt install sqlmap  (pre-installed on Kali)[/dim]")
    except subprocess.TimeoutExpired:
        console.print("  [yellow]  sqlmap timed out. Run manually: sqlmap -u '{url}' --batch[/yellow]")
    except Exception as e:
        console.print(f"  [red]  sqlmap error: {e}[/red]")

    console.print()


def _run_ssti(session: Session, console: Console):
    console.print("[bold cyan]  ── SSTI Detection ────────────────────────[/bold cyan]")
    console.print("  [dim]Testing template injection payloads against URL parameters...[/dim]")
    console.print()

    import requests, urllib.parse

    # SSTI detection payloads: payload → expected output substring
    payloads = {
        "{{7*7}}":       "49",      # Jinja2 / Twig
        "${7*7}":        "49",      # FreeMarker / Velocity
        "#{7*7}":        "49",      # EL (Java)
        "<%= 7*7 %>":   "49",      # ERB (Ruby)
        "${{7*7}}":      "49",      # Smarty
    }

    url_param = Prompt.ask(
        "  URL with injectable parameter (replace value with FUZZ)",
        default=session.target + "?search=FUZZ"
    )

    proxies = session.proxy_dict()
    found = False

    for payload, expected in payloads.items():
        test_url = url_param.replace("FUZZ", urllib.parse.quote(payload))
        try:
            r = requests.get(test_url, headers={"User-Agent": UA},
                             proxies=proxies, timeout=8, verify=False)
            if expected in r.text:
                console.print(f"  [bold red]✗ SSTI confirmed: payload={payload} → response contains '{expected}'[/bold red]")
                session.add_finding(
                    "CRITICAL", "Server-Side Template Injection (SSTI) detected",
                    f"Payload '{payload}' was evaluated server-side. Output contained '{expected}'.",
                    evidence=f"GET {test_url} → {expected} in response",
                    remediation="Never render user input directly in templates. Use sandboxed rendering or strict input validation.",
                    module="Injection"
                )
                found = True
            else:
                console.print(f"  [dim]  {payload:<20} → not triggered[/dim]")
        except Exception as e:
            console.print(f"  [dim]  {payload:<20} → error: {e}[/dim]")

    if not found:
        console.print("\n  [green]  No SSTI detected with standard payloads.[/green]")

    console.print()


def _run_open_redirect(session: Session, console: Console):
    console.print("[bold cyan]  ── Open Redirect Check ────────────────────[/bold cyan]")
    import requests

    redirect_payloads = [
        "//evil.com", "https://evil.com", "//evil.com/%2f..",
        "/\\evil.com", "https:evil.com", "javascript:alert(1)",
    ]
    common_params = ["url", "redirect", "next", "return", "returnUrl",
                     "goto", "dest", "destination", "continue", "r", "to"]

    proxies = session.proxy_dict()
    found = False

    for param in common_params:
        for payload in redirect_payloads[:2]:   # 2 payloads per param to keep it fast
            test_url = f"{session.target}?{param}={payload}"
            try:
                r = requests.get(test_url, headers={"User-Agent": UA},
                                 proxies=proxies, timeout=6,
                                 verify=False, allow_redirects=False)
                loc = r.headers.get("location", "")
                if "evil.com" in loc or payload in loc:
                    console.print(f"  [bold red]✗ Open redirect: ?{param}={payload} → Location: {loc}[/bold red]")
                    session.add_finding(
                        "MEDIUM", "Open redirect detected",
                        f"Parameter '{param}' allows unvalidated redirects to external URLs.",
                        evidence=f"GET ?{param}={payload} → Location: {loc}",
                        remediation="Validate redirect targets against an allowlist of known-good domains.",
                        module="Injection"
                    )
                    found = True
                else:
                    console.print(f"  [dim]  ?{param}={payload} → {r.status_code}[/dim]")
            except Exception:
                pass

    if not found:
        console.print("\n  [green]  No open redirect found for common parameters.[/green]")

    console.print()


def _run_csrf_check(session: Session, console: Console):
    console.print("[bold cyan]  ── CSRF Header Analysis ───────────────────[/bold cyan]")
    import requests

    proxies = session.proxy_dict()
    try:
        r = requests.get(session.target,
                         headers={"User-Agent": UA},
                         proxies=proxies, timeout=10, verify=False)

        # Check for CSRF-relevant headers
        cors_origin = r.headers.get("Access-Control-Allow-Origin", "")
        cors_creds  = r.headers.get("Access-Control-Allow-Credentials", "")
        csrf_token_in_page = "csrf" in r.text.lower() or "_token" in r.text.lower()

        if cors_origin == "*":
            console.print("  [bold red]✗ Access-Control-Allow-Origin: *  (wildcard CORS — high risk)[/bold red]")
            session.add_finding(
                "HIGH", "Wildcard CORS policy",
                "The server allows any origin, which combined with credentials could enable CSRF.",
                evidence="Access-Control-Allow-Origin: *",
                remediation="Restrict CORS to specific trusted origins.",
                module="Injection"
            )
        elif cors_origin:
            console.print(f"  [green]  CORS origin: {cors_origin}[/green]")
        else:
            console.print("  [dim]  No CORS headers found.[/dim]")

        if cors_creds.lower() == "true" and cors_origin == "*":
            console.print("  [bold red]✗ CORS: Allow-Credentials=true with wildcard origin — critical![/bold red]")
            session.add_finding(
                "CRITICAL", "CORS misconfiguration: credentials with wildcard",
                "Allow-Credentials: true combined with wildcard origin allows cross-site credential theft.",
                evidence="Access-Control-Allow-Credentials: true + Allow-Origin: *",
                remediation="Never combine credentials: true with wildcard origin.",
                module="Injection"
            )

        if csrf_token_in_page:
            console.print("  [green]  CSRF token pattern detected in page HTML (good sign).[/green]")
        else:
            console.print("  [yellow]  No CSRF token pattern detected in page HTML.[/yellow]")
            session.add_finding(
                "MEDIUM", "No CSRF token detected in page",
                "No CSRF token pattern found. Forms may be vulnerable to cross-site request forgery.",
                evidence="No csrf/token fields found in page source",
                remediation="Implement synchronizer token pattern (CSRF token) in all state-changing forms.",
                module="Injection"
            )

    except Exception as e:
        console.print(f"  [red]  CSRF check error: {e}[/red]")

    console.print()
