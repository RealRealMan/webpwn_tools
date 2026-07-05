"""
CMS detection — fingerprint the target CMS from headers, paths, and page content.
Supports: WordPress, Joomla, Drupal, Magento, custom/static.
Also detects managed SaaS site builders (Wix, Squarespace, Shopify, Webflow)
so we don't misfire CMS-specific scanners against platforms that aren't
self-hosted open-source CMSs.
"""
import requests
import re
from urllib.parse import urljoin

TIMEOUT = 10
UA = "Mozilla/5.0 (compatible; WebPwnTools/2.0; security-assessment)"

# Checked FIRST — these are managed SaaS platforms. If matched, we report
# them directly instead of trying to fingerprint an open-source CMS,
# since path-based CMS probes produce false positives on these platforms
# (SaaS builders often 200/redirect on arbitrary paths).
SAAS_SIGNATURES = {
    "Wix": {
        "headers": {"x-wix-request-id": None, "x-wix-renderer-server": None},
        "body":    [r'wixstatic\.com', r'wix\.com/website', r'X-Wix-'],
        "ns":      [r'wixdns\.net'],
    },
    "Squarespace": {
        "headers": {"x-servedby": ["squarespace"]},
        "body":    [r'squarespace\.com', r'static1\.squarespace\.com'],
        "ns":      [r'squarespacedns\.com'],
    },
    "Shopify": {
        "headers": {"x-shopid": None, "x-shardid": None},
        "body":    [r'cdn\.shopify\.com', r'Shopify\.theme'],
        "ns":      [r'shopify\.com'],
    },
    "Webflow": {
        "headers": {"x-wf-page-id": None},
        "body":    [r'assets-global\.website-files\.com', r'webflow\.com'],
        "ns":      [r'webflow\.io'],
    },
}

CMS_SIGNATURES = {
    "WordPress": {
        "paths":   ["/wp-login.php", "/wp-admin/", "/wp-content/"],
        "headers": {"x-powered-by": ["wordpress"]},
        "body":    [r'wp-content', r'wp-includes', r'WordPress', r'xmlrpc\.php'],
        "meta":    [r'<meta name=["\']generator["\'] content=["\']WordPress'],
    },
    "Joomla": {
        "paths":   ["/administrator/", "/components/", "/modules/"],
        "headers": {},
        "body":    [r'/components/com_', r'Joomla!', r'joomla\.org', r'/media/jui/'],
        "meta":    [r'<meta name=["\']generator["\'] content=["\']Joomla'],
    },
    "Drupal": {
        "paths":   ["/user/login", "/sites/default/"],
        "headers": {"x-generator": ["drupal"], "x-drupal-cache": None},
        "body":    [r'Drupal\.settings', r'drupal\.js', r'/sites/default/files'],
        "meta":    [r'<meta name=["\']generator["\'] content=["\']Drupal'],
    },
    "Magento": {
        "paths":   ["/skin/frontend/", "/js/mage/"],
        "headers": {},
        "body":    [r'Mage\.Cookies', r'/skin/frontend/', r'magento'],
        "meta":    [],
    },
}


def _get_ns_records(domain: str) -> str:
    """Best-effort NS record lookup via dig, used to catch SaaS platforms
    that don't leave clear body/header fingerprints."""
    import subprocess
    try:
        r = subprocess.run(["dig", "+short", domain, "NS"],
                           capture_output=True, text=True, timeout=6)
        return r.stdout.lower()
    except Exception:
        return ""


def detect_cms(target: str, proxy: str = None) -> str | None:
    """
    Return detected CMS/platform name string or None if unknown.
    Checks managed SaaS platforms first (Wix, Squarespace, Shopify, Webflow),
    then falls back to open-source CMS fingerprinting (WordPress, Joomla,
    Drupal, Magento). Open-source CMS detection now requires at least one
    body/meta/header signal — path-probing alone (which is prone to false
    positives on SaaS platforms returning 200/redirect for any path) is
    only used as a secondary confirmation signal, not sole evidence.
    """
    proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"} if proxy else None
    headers = {"User-Agent": UA}

    try:
        r = requests.get(target, headers=headers, proxies=proxies,
                         timeout=TIMEOUT, verify=False, allow_redirects=True)
    except Exception:
        return None

    body      = r.text
    resp_hdrs = {k.lower(): v.lower() for k, v in r.headers.items()}

    from urllib.parse import urlparse
    domain = urlparse(target).netloc
    ns_records = _get_ns_records(domain)

    # ── Step 1: SaaS platform check (short-circuits open-source CMS scan) ──
    for platform, sigs in SAAS_SIGNATURES.items():
        score = 0
        for hdr, values in sigs["headers"].items():
            if hdr in resp_hdrs:
                score += 3
        for pattern in sigs["body"]:
            if re.search(pattern, body, re.IGNORECASE):
                score += 3
        for pattern in sigs.get("ns", []):
            if re.search(pattern, ns_records, re.IGNORECASE):
                score += 4
        if score >= 3:
            return f"{platform} (Managed SaaS)"

    # ── Step 2: Open-source CMS fingerprinting ──
    scores = {cms: {"content_hit": False, "score": 0} for cms in CMS_SIGNATURES}

    for cms, sigs in CMS_SIGNATURES.items():
        # Header signals — strong evidence
        for hdr, values in sigs["headers"].items():
            if hdr in resp_hdrs:
                if values is None or any(v in resp_hdrs[hdr] for v in values):
                    scores[cms]["score"] += 3
                    scores[cms]["content_hit"] = True

        # Body / meta signals — strong evidence
        for pattern in sigs["body"] + sigs["meta"]:
            if re.search(pattern, body, re.IGNORECASE):
                scores[cms]["score"] += 2
                scores[cms]["content_hit"] = True

        # Path probing — weak evidence only (many false positives on
        # catch-all-routing platforms), used to add confidence, not decide alone
        for path in sigs["paths"][:2]:
            try:
                pr = requests.head(urljoin(target, path), headers=headers,
                                   proxies=proxies, timeout=6,
                                   verify=False, allow_redirects=False)
                if pr.status_code in (200, 301, 302, 403):
                    scores[cms]["score"] += 1
            except Exception:
                pass

    # Require BOTH a minimum score AND at least one real content/header hit
    # (not just path-probe hits) to avoid false-positives like SaaS sites
    # scoring on generic 200/403 responses to /administrator/ etc.
    best_cms = max(scores, key=lambda c: scores[c]["score"])
    if scores[best_cms]["score"] >= 4 and scores[best_cms]["content_hit"]:
        return best_cms

    return None

