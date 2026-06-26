# WebPwn Tools v2.0

Universal Web Penetration Testing Toolkit for Kali Linux.

## Quick start
```bash
pip3 install rich pyyaml requests --break-system-packages
python3 webpwn.py
```

## With Burp Suite proxy
```bash
python3 webpwn.py --proxy 127.0.0.1:8080
```

## Non-interactive (single module)
```bash
python3 webpwn.py --target https://site.com --module 2   # Headers & TLS
python3 webpwn.py --target https://site.com --module 7   # CMS scan
python3 webpwn.py --target https://site.com --no-splash  # Skip animation
```

## Modules
| Key | Module | Tools |
|-----|--------|-------|
| 1 | Recon & Fingerprint | whois, dig, httpx, whatweb |
| 2 | Headers & TLS | curl, testssl.sh |
| 3 | Dir & File Enum | gobuster, feroxbuster |
| 4 | Injection Tests | dalfox, sqlmap, custom |
| 5 | Auth Testing | hydra, custom |
| 6 | API & JS Recon | custom |
| 7 | CMS Scanner | wpscan / joomscan / droopescan |
| 8 | User Enumeration | CMS-specific |
| 9 | Generate Report | HTML output |
| 0 | Settings | config.yaml |

## WPScan API token
Get a free token at https://wpscan.com, then:
- Set in Settings [0] inside the tool, OR
- Export: `export WPSCAN_TOKEN=your_token_here`

## Config file
`~/.config/webpwn/config.yaml`

## ⚠ Legal
For authorized security testing only.
