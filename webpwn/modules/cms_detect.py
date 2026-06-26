"""
CMS detection — fingerprint the target CMS from headers, paths, and page content.
Supports: WordPress, Joomla, Drupal, Magento, custom/static.
"""
import requests
import re
from urllib.parse import urljoin

TIMEOUT = 10
UA = "Mozilla/5.0 (compatible; WebPwnTools/2.0; security-assessment)"

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
        "body":    [r'/components/com_', r'Joomla!', r'joomla'],
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


def detect_cms(target: str, proxy: str = None) -> str | None:
    """
    Return detected CMS name string or None if unknown.
    Tries headers, known paths, and body signatures.
    """
    proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"} if proxy else None
    headers = {"User-Agent": UA}

    try:
        r = requests.get(target, headers=headers, proxies=proxies,
                         timeout=TIMEOUT, verify=False, allow_redirects=True)
    except Exception:
        return None

    body    = r.text.lower()
    resp_hdrs = {k.lower(): v.lower() for k, v in r.headers.items()}

    scores = {cms: 0 for cms in CMS_SIGNATURES}

    for cms, sigs in CMS_SIGNATURES.items():
        # Header signals
        for hdr, values in sigs["headers"].items():
            if hdr in resp_hdrs:
                if values is None:
                    scores[cms] += 3
                elif any(v in resp_hdrs[hdr] for v in values):
                    scores[cms] += 3

        # Body / meta signals
        for pattern in sigs["body"] + sigs["meta"]:
            if re.search(pattern, r.text, re.IGNORECASE):
                scores[cms] += 2

        # Path probing (lightweight HEAD requests)
        for path in sigs["paths"][:2]:   # limit to 2 paths per CMS
            try:
                pr = requests.head(urljoin(target, path), headers=headers,
                                   proxies=proxies, timeout=6,
                                   verify=False, allow_redirects=False)
                if pr.status_code in (200, 301, 302, 403):
                    scores[cms] += 2
            except Exception:
                pass

    best_cms = max(scores, key=scores.get)
    if scores[best_cms] >= 4:
        return best_cms
    return None
