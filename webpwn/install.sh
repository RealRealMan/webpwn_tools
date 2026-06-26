#!/bin/bash
# WebPwn Tools v2.0 - Kali Linux installer

echo "[*] Installing WebPwn Tools v2.0..."

# Python deps
pip3 install rich pyyaml requests --break-system-packages -q

# Create dirs
mkdir -p ~/.config/webpwn ~/webpwn/reports

# Make executable
chmod +x webpwn.py

# Optional: symlink to PATH
# sudo ln -sf $(pwd)/webpwn.py /usr/local/bin/webpwn

echo "[+] Done. Run: python3 webpwn.py"
echo "[+] Or with target: python3 webpwn.py --target ponzurestaurant.nl --proxy 127.0.0.1:8080"
echo ""
echo "[*] Kali tools used (all pre-installed on Kali):"
echo "    wpscan, gobuster, sqlmap, whatweb, hydra, whois, dig"
echo "    Optional: testssl.sh, dalfox, feroxbuster, joomscan, droopescan"
