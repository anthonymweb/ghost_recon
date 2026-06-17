from datetime import datetime
from typing import Dict, Any
from pathlib import Path

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

RISK_COLORS = {
    "CRITICAL": "#E74C3C",
    "HIGH": "#E67E22",
    "MEDIUM": "#F39C12",
    "LOW": "#2ECC71",
    "INFO": "#3498DB",
    "CLEAN": "#2ECC71",
    "SUSPICIOUS": "#F39C12",
    "MALICIOUS": "#E74C3C",
    "UNKNOWN": "#95A5A6",
}


def generate(results: Dict[str, Any], target: str, output_name: str = None) -> str:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = output_name or f"{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    filepath = REPORTS_DIR / f"{filename}.html"

    risk_score, risk_label = _calculate_risk(results)

    dns = results.get("dns", {})
    whois = results.get("whois", {})
    subs = results.get("subdomains", {})
    shodan_data = results.get("shodan", {})
    hibp_data = results.get("hibp", {})
    github_data = results.get("github_dorks", {})
    vt_data = results.get("virustotal", {})

    modules_run = [k for k, v in results.items() if v.get("error") != "Skipped (no API key)"]
    modules_run_str = ", ".join(modules_run)
    if not modules_run_str:
        modules_run_str = "None"

    total_dns = sum(len(v) for v in dns.get("records", {}).values())
    whois_expiring = "Yes" if whois.get("expiring_soon") else "No"
    sub_count = len(subs.get("confirmed_live", []))
    port_count = len(shodan_data.get("ports", []))
    breach_count = hibp_data.get("total_breaches", 0)
    vt_malicious = vt_data.get("malicious_count", 0)
    github_count = github_data.get("total_findings", 0)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GhostRecon Report — {target}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;700&display=swap');
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: #0D0D0D; color: #E0E0E0; font-family: 'JetBrains Mono', monospace; min-height: 100vh; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
  .header {{ text-align: center; padding: 3rem 0; border-bottom: 1px solid #1A1A2E; }}
  .logo {{ color: #00FFFF; font-size: 1.4rem; font-weight: 700; letter-spacing: 2px; }}
  .logo span {{ color: #9B59B6; }}
  .tagline {{ color: #666; font-size: 0.8rem; margin-top: 0.5rem; }}
  .meta {{ margin-top: 1rem; font-size: 0.75rem; color: #888; }}
  .meta strong {{ color: #00FFFF; }}
  .risk-badge {{ display: inline-block; padding: 0.5rem 2rem; border-radius: 4px; font-weight: 700; font-size: 1.2rem; margin-top: 1rem; }}
  .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; padding: 2rem 0; }}
  .card {{ background: #1A1A2E; border: 1px solid #2A2A4E; border-radius: 8px; padding: 1.5rem; text-align: center; }}
  .card-value {{ font-size: 2rem; font-weight: 700; margin-bottom: 0.3rem; }}
  .card-label {{ font-size: 0.7rem; color: #888; text-transform: uppercase; letter-spacing: 1px; }}
  .card.card-critical .card-value {{ color: #E74C3C; }}
  .card.card-high .card-value {{ color: #E67E22; }}
  .card.card-medium .card-value {{ color: #F39C12; }}
  .card.card-info .card-value {{ color: #3498DB; }}
  .card.card-clean .card-value {{ color: #2ECC71; }}
  section {{ margin: 2rem 0; }}
  .section-title {{ color: #00FFFF; font-size: 1rem; font-weight: 700; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 2px solid #9B59B6; }}
  details {{ background: #1A1A2E; border: 1px solid #2A2A4E; border-radius: 8px; margin-bottom: 1rem; overflow: hidden; }}
  details summary {{ padding: 1rem; cursor: pointer; font-weight: 700; color: #9B59B6; outline: none; }}
  details summary:hover {{ background: #222244; }}
  details .content {{ padding: 1rem; border-top: 1px solid #2A2A4E; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.75rem; }}
  th {{ text-align: left; padding: 0.5rem; color: #00FFFF; border-bottom: 1px solid #333; font-weight: 700; }}
  td {{ padding: 0.5rem; border-bottom: 1px solid #1A1A2E; }}
  .tag {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.65rem; font-weight: 700; }}
  .tag-critical {{ background: #E74C3C33; color: #E74C3C; border: 1px solid #E74C3C; }}
  .tag-high {{ background: #E67E2233; color: #E67E22; border: 1px solid #E67E22; }}
  .tag-medium {{ background: #F39C1233; color: #F39C12; border: 1px solid #F39C12; }}
  .tag-low {{ background: #2ECC7133; color: #2ECC71; border: 1px solid #2ECC71; }}
  .tag-info {{ background: #3498DB33; color: #3498DB; border: 1px solid #3498DB; }}
  .footer {{ text-align: center; padding: 2rem 0; border-top: 1px solid #1A1A2E; font-size: 0.7rem; color: #555; }}
  .footer strong {{ color: #9B59B6; }}
  .disclaimer {{ background: #1A0000; border: 1px solid #E74C3C; border-radius: 8px; padding: 1rem; margin-top: 1rem; font-size: 0.7rem; color: #E74C3C; text-align: center; }}
  a {{ color: #00FFFF; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .no-data {{ color: #666; font-style: italic; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="logo">GHOSTRECON <span>v1.0</span></div>
    <div class="tagline">by GhostChain — Passive OSINT Recon Engine</div>
    <div class="meta">
      <strong>Target:</strong> {target} &nbsp;|&nbsp; <strong>Scanned:</strong> {timestamp}<br>
      <strong>Modules:</strong> {modules_run_str}
    </div>
    <div class="risk-badge" style="background: {RISK_COLORS.get(risk_label, '#95A5A6')}33; color: {RISK_COLORS.get(risk_label, '#95A5A6')}; border: 2px solid {RISK_COLORS.get(risk_label, '#95A5A6')}">
      RISK: {risk_label}
    </div>
    <div style="margin-top: 0.5rem; font-size: 0.8rem; color: #888;">Score: {risk_score}/100</div>
  </div>

  <div class="summary">
    <div class="card{' card-info' if sub_count == 0 else ' card-high'}">
      <div class="card-value" style="color: {RISK_COLORS['INFO'] if sub_count == 0 else RISK_COLORS['MEDIUM']}">{sub_count}</div>
      <div class="card-label">Subdomains Found</div>
    </div>
    <div class="card{' card-info' if port_count == 0 else ' card-medium'}">
      <div class="card-value" style="color: {RISK_COLORS['INFO'] if port_count == 0 else RISK_COLORS['MEDIUM']}">{port_count}</div>
      <div class="card-label">Open Ports</div>
    </div>
    <div class="card{' card-clean' if breach_count == 0 else ' card-critical'}">
      <div class="card-value" style="color: {RISK_COLORS['CLEAN'] if breach_count == 0 else RISK_COLORS['CRITICAL']}">{breach_count}</div>
      <div class="card-label">Breaches Found</div>
    </div>
    <div class="card{' card-clean' if vt_malicious == 0 else ' card-critical'}">
      <div class="card-value" style="color: {RISK_COLORS['CLEAN'] if vt_malicious == 0 else RISK_COLORS['CRITICAL']}">{vt_malicious}</div>
      <div class="card-label">Malicious Flags</div>
    </div>
    <div class="card{' card-clean' if github_count == 0 else ' card-high'}">
      <div class="card-value" style="color: {RISK_COLORS['CLEAN'] if github_count == 0 else RISK_COLORS['HIGH']}">{github_count}</div>
      <div class="card-label">GitHub Leaks</div>
    </div>
  </div>
"""

    # DNS section
    html += "<section><div class='section-title'>DNS Records</div>"
    if dns.get("records"):
        for rtype, records in dns["records"].items():
            html += f"<details><summary>{rtype} Records ({len(records)})</summary><div class='content'>"
            for rec in records:
                html += f"<div style='padding: 0.3rem 0; font-size: 0.75rem;'><span class='tag tag-info'>{rtype}</span> {rec}</div>"
            html += "</div></details>"
    else:
        html += f"<div class='no-data'>{'No DNS records found' if not dns.get('error') else dns['error']}</div>"
    html += "</section>"

    # WHOIS section
    html += "<section><div class='section-title'>WHOIS Information</div>"
    if not whois.get("error"):
        items = [
            ("Registrar", whois.get("registrar"), "info"),
            ("Creation Date", whois.get("creation_date"), "info"),
            ("Expiration Date", whois.get("expiration_date"), "medium" if whois.get("expiring_soon") else "info"),
            ("Registrant Org", whois.get("registrant_org"), "info"),
            ("Expiring Soon", whois_expiring, "high" if whois.get("expiring_soon") else "low"),
        ]
        for label, value, severity in items:
            if value:
                tag_class = f"tag-{severity}"
                html += f"<div style='padding: 0.3rem 0; font-size: 0.75rem;'><span class='tag {tag_class}'>{label}</span> {value}</div>"
        if whois.get("name_servers"):
            html += f"<details style='margin-top: 0.5rem;'><summary>Name Servers ({len(whois['name_servers'])})</summary><div class='content'>"
            for ns in whois["name_servers"]:
                html += f"<div style='font-size: 0.75rem; padding: 0.2rem 0;'>{ns}</div>"
            html += "</div></details>"
    else:
        html += f"<div class='no-data'>{whois['error']}</div>"
    html += "</section>"

    # Subdomains section
    html += "<section><div class='section-title'>Subdomain Enumeration</div>"
    live = subs.get("confirmed_live", [])
    if live:
        html += f"<table><tr><th>Subdomain</th><th>IP Addresses</th></tr>"
        for s in live:
            ips = ", ".join(s.get("ips", []))
            html += f"<tr><td>{s['subdomain']}</td><td>{ips}</td></tr>"
        html += "</table>"
    else:
        html += f"<div class='no-data'>No live subdomains discovered</div>"
    crt_count = subs.get("crt_sh_count", 0)
    brute_count = len(subs.get("bruteforce_found", []))
    html += f"<div style='margin-top: 0.5rem; font-size: 0.7rem; color: #666;'>crt.sh: {crt_count} candidates | Brute-force: {brute_count} resolved</div>"
    html += "</section>"

    # Shodan section
    html += "<section><div class='section-title'>Shodan — Open Ports & Services</div>"
    if shodan_data.get("api_key_missing"):
        html += f"<div class='no-data'>Shodan API key not configured</div>"
    elif shodan_data.get("error"):
        html += f"<div class='no-data'>{shodan_data['error']}</div>"
    elif shodan_data.get("services"):
        html += "<table><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Version</th></tr>"
        for svc in shodan_data["services"]:
            html += f"<tr><td>{svc.get('port', '')}</td><td>{svc.get('protocol', '')}</td><td>{svc.get('service', '')}</td><td>{svc.get('product', '')}</td><td>{svc.get('version', '')}</td></tr>"
        html += "</table>"
        vulns = shodan_data.get("vulnerabilities", [])
        if vulns:
            html += "<div style='margin-top: 0.5rem;'><span class='tag tag-critical'>CVEs</span> "
            for v in vulns:
                html += f"<span style='color: #E74C3C;'>{v}</span> "
            html += "</div>"
    else:
        html += "<div class='no-data'>No services discovered</div>"
    html += "</section>"

    # HIBP section
    html += "<section><div class='section-title'>HaveIBeenPwned — Breach Check</div>"
    if hibp_data.get("api_key_missing"):
        html += f"<div class='no-data'>HIBP API key not configured</div>"
    elif hibp_data.get("breaches"):
        html += "<table><tr><th>Breach Name</th><th>Domain</th><th>Date</th><th>Data Classes</th></tr>"
        for b in hibp_data["breaches"]:
            classes = ", ".join(b.get("data_classes", []))
            html += f"<tr><td>{b.get('name', '')}</td><td>{b.get('domain', '')}</td><td>{b.get('date', '')}</td><td style='font-size: 0.65rem;'>{classes}</td></tr>"
        html += "</table>"
    else:
        html += f"<div class='no-data'>No breaches detected for common email patterns</div>"
    html += "</section>"

    # GitHub Dorks section
    html += "<section><div class='section-title'>GitHub Dorking</div>"
    if github_data.get("results"):
        html += "<table><tr><th>Keyword</th><th>Repository</th><th>File</th></tr>"
        for item in github_data["results"]:
            repo = item.get("repository", "")
            file_url = item.get("url", "")
            file_name = item.get("file", "")
            kw = item.get("keyword", "")
            if item.get("error") == "Rate limited":
                html += f"<tr><td>{kw}</td><td colspan='2'><span style='color: #F39C12;'>Rate limited — add GitHub token</span></td></tr>"
            else:
                html += f"<tr><td>{kw}</td><td>{repo}</td><td><a href='{file_url}' target='_blank'>{file_name}</a></td></tr>"
        html += "</table>"
    else:
        html += "<div class='no-data'>No exposed secrets found on GitHub</div>"
    html += "</section>"

    # VirusTotal section
    html += "<section><div class='section-title'>VirusTotal — Domain Reputation</div>"
    if vt_data.get("api_key_missing"):
        html += f"<div class='no-data'>VirusTotal API key not configured</div>"
    elif vt_data.get("error"):
        html += f"<div class='no-data'>{vt_data['error']}</div>"
    else:
        risk = vt_data.get("risk_level", "UNKNOWN")
        risk_color = RISK_COLORS.get(risk, "#95A5A6")
        html += f"""
        <div style='display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 0.5rem; margin-bottom: 1rem;'>
          <div style='background: #1A1A2E; padding: 1rem; border-radius: 8px; text-align: center;'><div style='font-size: 1.5rem; font-weight: 700; color: {risk_color};'>{risk}</div><div style='font-size: 0.6rem; color: #888; text-transform: uppercase;'>Risk Level</div></div>
          <div style='background: #1A1A2E; padding: 1rem; border-radius: 8px; text-align: center;'><div style='font-size: 1.5rem; font-weight: 700; color: #E74C3C;'>{vt_data.get('malicious_count', 0)}</div><div style='font-size: 0.6rem; color: #888; text-transform: uppercase;'>Malicious</div></div>
          <div style='background: #1A1A2E; padding: 1rem; border-radius: 8px; text-align: center;'><div style='font-size: 1.5rem; font-weight: 700; color: #F39C12;'>{vt_data.get('suspicious_count', 0)}</div><div style='font-size: 0.6rem; color: #888; text-transform: uppercase;'>Suspicious</div></div>
          <div style='background: #1A1A2E; padding: 1rem; border-radius: 8px; text-align: center;'><div style='font-size: 1.5rem; font-weight: 700; color: #2ECC71;'>{vt_data.get('harmless_count', 0)}</div><div style='font-size: 0.6rem; color: #888; text-transform: uppercase;'>Harmless</div></div>
        </div>"""
        if vt_data.get("categories"):
            cats = "<br>".join([f"<strong>{k}:</strong> {v}" for k, v in vt_data["categories"].items()])
            html += f"<div style='font-size: 0.75rem;'>{cats}</div>"
    html += "</section>"

    # Footer
    html += f"""
  <div class='footer'>
    Generated by <strong>GhostRecon v1.0</strong> | <strong style='color:#00FFFF;'>GhostChain</strong> Project<br>
    Passive OSINT Reconnaissance Engine — Ethical Use Only
  </div>
  <div class='disclaimer'>
    ⚠ This report was generated for authorized security assessment purposes only.<br>
    Unauthorized use of this tool against targets you do not own or have explicit permission to test is illegal.<br>
    The operator is solely responsible for compliance with all applicable laws.
  </div>
</div>
</body>
</html>"""

    with open(filepath, "w") as f:
        f.write(html)

    return str(filepath)


def _calculate_risk(results: Dict[str, Any]) -> tuple:
    score = 0

    dns = results.get("dns", {})
    whois = results.get("whois", {})
    subs = results.get("subdomains", {})
    shodan_data = results.get("shodan", {})
    hibp_data = results.get("hibp", {})
    github_data = results.get("github_dorks", {})
    vt_data = results.get("virustotal", {})

    if whois.get("expiring_soon"):
        score += 10

    live_subs = len(subs.get("confirmed_live", []))
    if live_subs > 20:
        score += 15
    elif live_subs > 10:
        score += 10
    elif live_subs > 0:
        score += 5

    ports = len(shodan_data.get("ports", []))
    if ports > 10:
        score += 15
    elif ports > 5:
        score += 10
    elif ports > 0:
        score += 5

    vulns = len(shodan_data.get("vulnerabilities", []))
    score += min(vulns * 5, 20)

    breaches = hibp_data.get("total_breaches", 0)
    score += min(breaches * 10, 25)

    vt_mal = vt_data.get("malicious_count", 0)
    score += min(vt_mal * 5, 20)

    github_findings = github_data.get("total_findings", 0)
    score += min(github_findings * 3, 15)

    score = min(score, 100)

    if score >= 70:
        label = "CRITICAL"
    elif score >= 50:
        label = "HIGH"
    elif score >= 30:
        label = "MEDIUM"
    elif score >= 10:
        label = "LOW"
    else:
        label = "INFO"

    return score, label
