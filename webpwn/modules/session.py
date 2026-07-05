"""
Session state — holds target, findings, config for the current run.
"""
import datetime
import os


class Session:
    def __init__(self, config: dict):
        self.session_id  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.target      = config.get("target", "")
        self.proxy       = config.get("proxy", None)
        self.cms         = config.get("cms", None)
        self.threads     = config.get("threads", 10)
        self.rate_limit  = config.get("rate_limit", 50)
        self.wpscan_api  = config.get("wpscan_api", os.environ.get("WPSCAN_TOKEN", ""))
        self.report_dir  = config.get("report_dir",
                                      os.path.expanduser("~/webpwn/reports/"))
        self.wordlist    = config.get("wordlist",
                                      "/usr/share/wordlists/dirb/common.txt")
        self.findings    = []
        self.command_log = []

        # ── Structured target profile (populated by recon/headers/cms modules) ──
        self.target_profile = {
            # Identity
            "domain":           "",
            "subdomains":       [],   # list of str
            "ip_addresses":     [],   # list of str
            # Infrastructure
            "server":           "",
            "technologies":     [],   # list of str e.g. ["PHP/8.1", "Apache"]
            "cdn":              "",   # e.g. "Cloudflare", "Fastly"
            "hosting":          "",   # e.g. "Google Cloud", "AWS"
            # CMS
            "cms":              "",
            "cms_version":      "",
            # DNS
            "dns_mx":           [],
            "dns_ns":           [],
            "dns_txt":          [],
            # TLS / SSL
            "ssl_issuer":       "",
            "ssl_expiry":       "",
            "ssl_grade":        "",
            # WHOIS
            "whois_registrar":  "",
            "whois_created":    "",
            "whois_expiry":     "",
            "whois_org":        "",
            # Security headers quick summary (populated by headers_tls module)
            "headers_present":  [],
            "headers_missing":  [],
            # Open ports (if nmap run)
            "open_ports":       [],
        }

        # Engagement info (set via Settings, embedded in report)
        self.engagement = config.get("engagement", {
            "tester_name":   "",
            "client_name":   "",
            "date_start":    "",
            "date_end":      "",
            "auth_ref":      "",   # authorisation document / reference
            "scope":         "",
            "out_of_scope":  "",
        })

        os.makedirs(self.report_dir, exist_ok=True)

    # ── profile helpers ──────────────────────────────────────────────────────

    def set_profile(self, key: str, value):
        """Set a single profile field."""
        if key in self.target_profile:
            self.target_profile[key] = value

    def append_profile(self, key: str, value):
        """Append to a list profile field (deduplicating)."""
        if key in self.target_profile and isinstance(self.target_profile[key], list):
            if value and value not in self.target_profile[key]:
                self.target_profile[key].append(value)

    # ── findings ─────────────────────────────────────────────────────────────

    def add_finding(self, severity: str, title: str, description: str,
                    evidence: str = "", remediation: str = "", module: str = ""):
        self.findings.append({
            "id":          len(self.findings) + 1,
            "severity":    severity.upper(),
            "title":       title,
            "description": description,
            "evidence":    evidence,
            "remediation": remediation,
            "module":      module,
            "timestamp":   datetime.datetime.now().isoformat(),
        })

    def log_command(self, cmd: str, output: str = ""):
        self.command_log.append({
            "timestamp": datetime.datetime.now().isoformat(),
            "cmd":       cmd,
            "output":    output[:2000],
        })

    # ── proxy helpers ─────────────────────────────────────────────────────────

    def proxy_dict(self):
        if self.proxy:
            return {"http": f"http://{self.proxy}",
                    "https": f"http://{self.proxy}"}
        return None

    def proxy_flag(self):
        if self.proxy:
            return f"--proxy http://{self.proxy}"
        return ""

    # ── summary ───────────────────────────────────────────────────────────────

    def summary(self):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            sev = f["severity"]
            if sev in counts:
                counts[sev] += 1
        return counts
