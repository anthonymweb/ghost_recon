<p align="center">
  <img src="https://img.shields.io/badge/version-1.0-0F8B72?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-0F8B72?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/python-3.10%2B-0F8B72?style=flat-square" alt="Python">
  <img src="https://img.shields.io/badge/osint-passive-0F8B72?style=flat-square" alt="OSINT">
</p>

<br>

<p align="center">
  <code style="font-size: 2.5rem; font-weight: 800; letter-spacing: 6px; color: #0F8B72;">GHOSTRECON</code>
</p>

<p align="center">
  <strong>Passive OSINT Reconnaissance Engine</strong><br>
  <sub>by GhostChain &mdash; Ethical security research only</sub>
</p>

<br>

<p align="center">
  <img src="https://img.shields.io/badge/DNS-Enumeration-0F8B72?style=for-the-badge&logo=internetexplorer&logoColor=white" alt="DNS">
  <img src="https://img.shields.io/badge/WHOIS-Lookup-0F8B72?style=for-the-badge&logo=whois&logoColor=white" alt="WHOIS">
  <img src="https://img.shields.io/badge/Subdomain-Discovery-0F8B72?style=for-the-badge&logo=googlecloud&logoColor=white" alt="Subdomains">
  <img src="https://img.shields.io/badge/Shodan-Recon-0F8B72?style=for-the-badge&logo=shodan&logoColor=white" alt="Shodan">
  <img src="https://img.shields.io/badge/VirusTotal-Reputation-0F8B72?style=for-the-badge&logo=virustotal&logoColor=white" alt="VirusTotal">
  <img src="https://img.shields.io/badge/HIBP-Breach%20Check-0F8B72?style=for-the-badge&logo=haveibeenpwned&logoColor=white" alt="HIBP">
  <img src="https://img.shields.io/badge/GitHub-Dorking-0F8B72?style=for-the-badge&logo=github&logoColor=white" alt="GitHub Dorking">
</p>

<br>

---

## Overview

**GhostRecon** is a passive OSINT reconnaissance engine built for ethical hackers and security researchers. It gathers publicly available information about a domain without sending a single packet to the target — no active scanning, no exploitation, no `nmap`.

All reconnaissance is performed through third-party APIs, certificate transparency logs, and public DNS resolution.

---

## Features

| Module | What it does | API key needed |
|--------|-------------|:---:|
| **DNS Enumeration** | A, AAAA, MX, NS, TXT, CNAME, SOA records | |
| **WHOIS Lookup** | Registrar, dates, name servers, expiry alerts | |
| **Subdomain Discovery** | crt.sh certificate transparency + brute-force resolution | |
| **Shodan Recon** | Open ports, services, banners, CVEs | &#10003; |
| **HaveIBeenPwned** | Email breach checks against common patterns | &#10003; |
| **GitHub Dorking** | Searches for leaked passwords, tokens, secrets | &#10003; |
| **VirusTotal** | Domain reputation, malicious/suspicious counts | &#10003; |

GhostRecon works out of the box with zero API keys. Add keys for extended modules.

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/anthonymweb/ghost_recon.git
cd ghost_recon/ghostrecon
pip install -r requirements.txt

# Full scan
python ghostrecon.py -t example.com

# Scan with specific modules
python ghostrecon.py -t example.com -m dns,whois,subdomains

# With API keys
python ghostrecon.py -t example.com --shodan-key YOUR_KEY --vt-key YOUR_KEY
```

Reports are saved to `ghostrecon/reports/` as standalone HTML files.

---

## Web UI

GhostRecon ships with a built-in web interface for managing scans and API keys from your browser.

```bash
cd ghostrecon
python web/server.py
```

Open **http://localhost:8080** in your browser.

The web UI lets you:

- Enter a target domain and run scans with one click
- Manage API keys directly from the interface
- Select which modules to run
- View scan results in real-time with collapsible sections
- Open the full HTML report in a new tab
- Toggle between light and dark themes

<p align="center">
  <sub><em>Light and dark themes built in</em></sub>
</p>

---

## API Keys

GhostRecon is fully functional without any API keys. For extended modules, get free keys:

| Service | Get Key |
|---------|---------|
| [Shodan](https://account.shodan.io) | Open ports, services, CVEs |
| [VirusTotal](https://www.virustotal.com/gui/my-apikey) | Domain reputation |
| [HaveIBeenPwned](https://haveibeenpwned.com/API/Key) | Breach checking |
| [GitHub](https://github.com/settings/tokens) | Code/dork search |

Save keys in `config.yaml`:

```yaml
api_keys:
  shodan: "YOUR_SHODAN_KEY"
  virustotal: "YOUR_VT_KEY"
  hibp: "YOUR_HIBP_KEY"
  github: "YOUR_GITHUB_TOKEN"
```

---

## Command Line Options

```
-t, --target        Target domain to scan (required)
-o, --output        Custom report filename
-m, --modules       Comma-separated modules (default: all)
--shodan-key        Shodan API key
--vt-key            VirusTotal API key
--hibp-key          HIBP API key
--github-key        GitHub personal access token
-v, --verbose       Verbose output
```

---

## Example

```bash
$ python ghostrecon.py -t example.com -m dns,whois

╭──────────────────────────────────────╮
│          GHOSTRECON                   │
│                  v1.0                 │
╰──────────────────────────────────────╯
  by GhostChain · Passive OSINT Recon Engine · Ethical use only

  Target: example.com
  Started: 2026-06-18 11:30:00

  DNS Enumeration ─────────────────────
    A       93.184.216.34
    A       2606:2800:220:1:248:1893:25c8:1946
    MX      0 .
    NS      a.iana-servers.net.
    NS      b.iana-servers.net.

  WHOIS Lookup ───────────────────────
    Registrar     RESERVED-Internet Assigned Numbers Authority
    Created       1995-08-14
    Expires       2027-08-13
    Organization  Internet Corporation for Assigned Names

  Report saved → reports/example.com_20260618_113000.html
```

---

## Project Structure

```
ghostrecon/
  ghostrecon.py         CLI entry point
  config.yaml           API key configuration
  requirements.txt      Python dependencies
  modules/
    dns_recon.py        DNS enumeration
    whois_recon.py      WHOIS lookups
    subdomain_recon.py  Subdomain discovery (crt.sh + brute-force)
    shodan_recon.py     Shodan integration
    hibp_recon.py       HaveIBeenPwned integration
    github_dorks.py     GitHub secret scanning
    virustotal_recon.py VirusTotal reputation
  output/
    report_generator.py HTML report generation
  utils/
    banner.py           Terminal banner
    config.py           Configuration loader
    logger.py           Terminal output styling
  web/
    server.py           Web UI server
    static/
      index.html        Web frontend
  reports/              Generated HTML reports
```

---

## Legal Disclaimer

GhostRecon is designed for **authorized security research and ethical use only**. You must own the target system or have explicit written permission from the owner before scanning. Unauthorized use is illegal in most jurisdictions.

**Know your laws. Get permission. Stay ethical.**

---

<p align="center">
  <strong>GhostRecon v1.0</strong> &middot; GhostChain Project &middot; MIT License<br>
  <sub>Built for the OWLSEC Cybersecurity Build Competition</sub>
</p>
