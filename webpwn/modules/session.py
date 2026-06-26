"""
Session state — holds target, findings, config for the current run.
"""
import uuid
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
        self.findings    = []   # list of Finding dicts
        self.command_log = []   # list of (timestamp, cmd, output) tuples
        os.makedirs(self.report_dir, exist_ok=True)

    def add_finding(self, severity: str, title: str, description: str,
                    evidence: str = "", remediation: str = "", module: str = ""):
        self.findings.append({
            "id":           len(self.findings) + 1,
            "severity":     severity.upper(),
            "title":        title,
            "description":  description,
            "evidence":     evidence,
            "remediation":  remediation,
            "module":       module,
            "timestamp":    datetime.datetime.now().isoformat(),
        })

    def log_command(self, cmd: str, output: str = ""):
        self.command_log.append({
            "timestamp": datetime.datetime.now().isoformat(),
            "cmd":       cmd,
            "output":    output[:2000],   # cap log size
        })

    def proxy_dict(self):
        """Return requests-compatible proxy dict, or None."""
        if self.proxy:
            return {"http": f"http://{self.proxy}",
                    "https": f"http://{self.proxy}"}
        return None

    def proxy_flag(self):
        """Return curl/tool proxy flag string, or empty string."""
        if self.proxy:
            return f"--proxy http://{self.proxy}"
        return ""

    def summary(self):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            sev = f["severity"]
            if sev in counts:
                counts[sev] += 1
        return counts
