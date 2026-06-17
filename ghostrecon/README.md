```
 ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██║  ███╗███████║██║   ██║███████╗   ██║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
                  by GhostChain | Passive OSINT Recon Engine v1.0
```

**GhostRecon** — passive OSINT reconnaissance engine for ethical hackers and security researchers. Part of the GhostChain open-source security toolkit.

## Features

- **DNS Enumeration** — A, AAAA, MX, NS, TXT, CNAME, SOA records via dnspython
- **WHOIS Lookup** — registrar, dates, name servers, expiry alerts (90-day window)
- **Subdomain Discovery** — crt.sh certificate transparency + brute-force resolution
- **Shodan Recon** — open ports, services, banners, CVEs (requires API key)
- **HaveIBeenPwned** — email breach checks against common patterns (requires API key)
- **GitHub Dorking** — searches for leaked passwords, tokens, secrets (requires token)
- **VirusTotal** — domain reputation, malicious/suspicious vendor counts (requires API key)
- **Live Terminal UI** — rich progress bars, color-coded findings, cyberpunk theme
- **Professional HTML Report** — standalone, dark theme, severity-tagged, risk scored
- **Passive Only** — no active scanning, no exploitation, no nmap

## Installation

```bash
git clone https://github.com/yourusername/ghostrecon.git
cd ghostrecon
pip install -r requirements.txt
```

## Usage

```bash
# Full scan (all modules)
python ghostrecon.py -t example.com

# Full scan with custom report name
python ghostrecon.py -t example.com -o my_report

# Run specific modules only
python ghostrecon.py -t example.com -m dns,whois,subdomains

# With API keys
python ghostrecon.py -t example.com --shodan-key YOUR_KEY --vt-key YOUR_KEY

# Verbose output
python ghostrecon.py -t example.com -v
```

## API Keys Setup

GhostRecon works out of the box with zero API keys for DNS, WHOIS, and subdomain enumeration. For extended modules, get free keys:

| Service | Module | Get Key |
|---------|--------|---------|
| Shodan | Open ports/services | https://account.shodan.io |
| VirusTotal | Domain reputation | https://www.virustotal.com/gui/my-apikey |
| HaveIBeenPwned | Breach checking | https://haveibeenpwned.com/API/Key |
| GitHub | Code/dork search | https://github.com/settings/tokens |

Add them to `config.yaml`:

```yaml
api_keys:
  shodan: "YOUR_SHODAN_KEY"
  virustotal: "YOUR_VT_KEY"
  hibp: "YOUR_HIBP_KEY"
  github: "YOUR_GITHUB_TOKEN"
```

## Example Output

```
[screenshot]

Terminal: color-coded live findings per module
Report: standalone HTML with stats dashboard and severity tags
```

## Legal Disclaimer

GhostRecon is designed for **authorized security research and ethical use only**. You must own the target system or have explicit written permission from the owner before scanning. Unauthorized use is illegal in most jurisdictions. The developers assume no liability and are not responsible for any misuse or damage caused by this tool.

Know your laws. Get permission. Stay ethical.

## GhostChain

```
Project    →  GhostRecon v1.0
Toolkit    →  GhostChain
Author     →  Mwebaza Tony
Contact    →  anthonymwebaza190@gmail.com
License    →  MIT
Purpose    →  Ethical security research only
```

Built for the OWLSEC $1,000 Cybersecurity Build Competition. Passive OSINT only. Authorized use only.

## License

MIT
