from datetime import datetime
from typing import Dict, Any
from pathlib import Path

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

RISK_COLORS = {
    "CRITICAL": "#EF4444",
    "HIGH": "#F97316",
    "MEDIUM": "#EAB308",
    "LOW": "#22C55E",
    "INFO": "#3B82F6",
    "CLEAN": "#22C55E",
    "SUSPICIOUS": "#EAB308",
    "MALICIOUS": "#EF4444",
    "UNKNOWN": "#6B7280",
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
  *, *::before, *::after {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    background: #0B0C10;
    color: #D1D5DB;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Inter', Roboto, sans-serif;
    line-height: 1.6;
    min-height: 100vh;
  }}
  .container {{ max-width: 1120px; margin: 0 auto; padding: 2.5rem 2rem; }}

  /* --- Header --- */
  .header {{
    text-align: center;
    padding: 3.5rem 2rem;
    background: linear-gradient(135deg, #0F111A 0%, #1A1D2E 100%);
    border: 1px solid #1F2237;
    border-radius: 16px;
    position: relative;
    overflow: hidden;
  }}
  .header::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: linear-gradient(90deg, #6366F1, #06B6D4, #6366F1);
    background-size: 200% 100%;
    animation: shimmer 4s ease-in-out infinite;
  }}
  @keyframes shimmer {{
    0%, 100% {{ background-position: 200% 0; }}
    50% {{ background-position: -200% 0; }}
  }}
  .logo {{
    font-size: 1.6rem;
    font-weight: 800;
    letter-spacing: 3px;
    background: linear-gradient(135deg, #E0E7FF, #67E8F9);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }}
  .logo span {{
    font-weight: 400;
    opacity: 0.6;
  }}
  .tagline {{ color: #6B7280; font-size: 0.85rem; margin-top: 0.4rem; }}
  .meta {{ margin-top: 1.25rem; font-size: 0.8rem; color: #6B7280; line-height: 1.8; }}
  .meta strong {{ color: #818CF8; font-weight: 600; }}
  .risk-section {{ display: flex; align-items: center; justify-content: center; gap: 1.5rem; margin-top: 1.5rem; flex-wrap: wrap; }}
  .risk-badge {{
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.5rem 1.5rem;
    border-radius: 99999px;
    font-weight: 700;
    font-size: 0.9rem;
    letter-spacing: 0.5px;
  }}
  .score-ring {{
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.85rem;
    color: #9CA3AF;
  }}
  .score-ring strong {{ font-size: 1.1rem; }}

  /* --- Summary Cards --- */
  .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-top: 2rem; }}
  .card {{
    background: #131620;
    border: 1px solid #1F2237;
    border-radius: 12px;
    padding: 1.5rem 1rem;
    text-align: center;
    transition: transform 0.2s, border-color 0.2s;
  }}
  .card:hover {{ transform: translateY(-2px); border-color: #374151; }}
  .card-value {{ font-size: 2rem; font-weight: 800; line-height: 1.2; }}
  .card-label {{ font-size: 0.7rem; color: #6B7280; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 0.3rem; }}

  /* --- Sections --- */
  section {{ margin-top: 2.5rem; }}
  .section-title {{
    font-size: 1rem;
    font-weight: 700;
    color: #E0E7FF;
    margin-bottom: 1rem;
    padding-bottom: 0.6rem;
    border-bottom: 1px solid #1F2237;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }}
  .section-title::before {{
    content: '';
    display: inline-block;
    width: 3px;
    height: 1.1rem;
    border-radius: 2px;
    background: linear-gradient(180deg, #6366F1, #06B6D4);
    flex-shrink: 0;
  }}

  /* --- Accordion --- */
  details {{
    background: #131620;
    border: 1px solid #1F2237;
    border-radius: 10px;
    margin-bottom: 0.75rem;
    transition: border-color 0.2s;
  }}
  details:hover {{ border-color: #374151; }}
  details[open] {{ border-color: #2D3060; }}
  details summary {{
    padding: 0.9rem 1.25rem;
    cursor: pointer;
    font-weight: 600;
    color: #A5B4FC;
    font-size: 0.85rem;
    outline: none;
    display: flex;
    align-items: center;
    justify-content: space-between;
    user-select: none;
  }}
  details summary::-webkit-details-marker {{ display: none; }}
  details summary::after {{
    content: '+';
    font-size: 1rem;
    color: #6B7280;
    transition: transform 0.2s;
  }}
  details[open] summary::after {{
    transform: rotate(45deg);
  }}
  details .content {{
    padding: 0.25rem 1.25rem 1rem;
    border-top: 1px solid #1F2237;
    font-size: 0.82rem;
  }}
  details .content > div {{ padding: 0.35rem 0; }}

  /* --- Tables --- */
  .table-wrap {{ overflow-x: auto; }}
  table {{ width: 100%; border-collapse: separate; border-spacing: 0; font-size: 0.8rem; }}
  thead th {{
    text-align: left;
    padding: 0.65rem 0.75rem;
    color: #818CF8;
    font-weight: 600;
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    background: #131620;
    border-bottom: 1px solid #1F2237;
  }}
  thead th:first-child {{ border-radius: 8px 0 0 0; }}
  thead th:last-child {{ border-radius: 0 8px 0 0; }}
  tbody tr {{ transition: background 0.15s; }}
  tbody tr:hover {{ background: rgba(99, 102, 241, 0.04); }}
  td {{
    padding: 0.6rem 0.75rem;
    border-bottom: 1px solid #1A1D2E;
    color: #D1D5DB;
  }}

  /* --- Tags / Badges --- */
  .tag {{
    display: inline-block;
    padding: 0.15rem 0.55rem;
    border-radius: 4px;
    font-size: 0.65rem;
    font-weight: 700;
    letter-spacing: 0.3px;
    font-family: 'SF Mono', 'Cascadia Code', 'JetBrains Mono', 'Consolas', monospace;
  }}
  .tag-critical {{ background: rgba(239, 68, 68, 0.15); color: #FCA5A5; border: 1px solid rgba(239, 68, 68, 0.3); }}
  .tag-high {{ background: rgba(249, 115, 22, 0.15); color: #FDBA74; border: 1px solid rgba(249, 115, 22, 0.3); }}
  .tag-medium {{ background: rgba(234, 179, 8, 0.15); color: #FDE047; border: 1px solid rgba(234, 179, 8, 0.3); }}
  .tag-low {{ background: rgba(34, 197, 94, 0.15); color: #86EFAC; border: 1px solid rgba(34, 197, 94, 0.3); }}
  .tag-info {{ background: rgba(59, 130, 246, 0.15); color: #93C5FD; border: 1px solid rgba(59, 130, 246, 0.3); }}

  .inline-tag {{
    display: inline-block;
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 600;
  }}
  .inline-critical {{ background: rgba(239, 68, 68, 0.12); color: #FCA5A5; }}
  .inline-high {{ background: rgba(249, 115, 22, 0.12); color: #FDBA74; }}
  .inline-medium {{ background: rgba(234, 179, 8, 0.12); color: #FDE047; }}
  .inline-low {{ background: rgba(34, 197, 94, 0.12); color: #86EFAC; }}
  .inline-info {{ background: rgba(59, 130, 246, 0.12); color: #93C5FD; }}

  .record-line {{
    display: flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0.35rem 0;
    font-size: 0.8rem;
    font-family: 'SF Mono', 'Cascadia Code', 'JetBrains Mono', 'Consolas', monospace;
  }}
  .record-value {{ color: #9CA3AF; word-break: break-all; }}

  .no-data {{ color: #6B7280; font-style: italic; padding: 0.5rem 0; font-size: 0.82rem; }}
  .sub-meta {{ margin-top: 0.6rem; font-size: 0.72rem; color: #6B7280; }}

  a {{ color: #67E8F9; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}

  /* --- CVE list --- */
  .cve-list {{ display: flex; flex-wrap: wrap; gap: 0.4rem; margin-top: 0.75rem; }}
  .cve-item {{
    display: inline-block;
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 600;
    font-family: 'SF Mono', 'Cascadia Code', 'JetBrains Mono', 'Consolas', monospace;
    background: rgba(239, 68, 68, 0.12);
    color: #FCA5A5;
  }}

  /* --- WHOIS grid --- */
  .whois-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 0.75rem; }}
  .whois-item {{
    background: #0F111A;
    border: 1px solid #1F2237;
    border-radius: 8px;
    padding: 0.75rem 1rem;
  }}
  .whois-label {{ font-size: 0.65rem; color: #6B7280; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 0.2rem; }}
  .whois-value {{ font-size: 0.82rem; color: #D1D5DB; word-break: break-all; }}

  /* --- VT stats grid --- */
  .vt-stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 0.75rem; }}
  .vt-stat {{
    background: #0F111A;
    border: 1px solid #1F2237;
    border-radius: 8px;
    padding: 1rem;
    text-align: center;
  }}
  .vt-stat-value {{ font-size: 1.4rem; font-weight: 700; }}
  .vt-stat-label {{ font-size: 0.6rem; color: #6B7280; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 0.2rem; }}

  /* --- Footer --- */
  .footer {{
    text-align: center;
    padding: 2rem 0;
    margin-top: 3rem;
    border-top: 1px solid #1F2237;
    font-size: 0.75rem;
    color: #6B7280;
  }}
  .footer strong {{ color: #818CF8; font-weight: 600; }}

  .disclaimer {{
    background: rgba(239, 68, 68, 0.06);
    border: 1px solid rgba(239, 68, 68, 0.2);
    border-radius: 10px;
    padding: 1rem 1.5rem;
    margin-top: 1.5rem;
    font-size: 0.72rem;
    color: #9CA3AF;
    text-align: center;
    line-height: 1.8;
  }}
  .disclaimer strong {{ color: #FCA5A5; }}

  @media (max-width: 640px) {{
    .container {{ padding: 1.25rem; }}
    .summary {{ grid-template-columns: 1fr 1fr; }}
    .whois-grid {{ grid-template-columns: 1fr; }}
    .vt-stats {{ grid-template-columns: 1fr 1fr; }}
  }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="logo">GHOSTRECON <span>v{risk_score if False else '1.0'}</span></div>
    <div class="tagline">by GhostChain — Passive OSINT Reconnaissance Engine</div>
    <div class="meta">
      <strong>Target:</strong> {target} &nbsp;·&nbsp; <strong>Scanned:</strong> {timestamp}<br>
      <strong>Modules:</strong> {modules_run_str}
    </div>
    <div class="risk-section">
      <div class="risk-badge" style="background: {RISK_COLORS.get(risk_label, '#6B7280')}18; color: {RISK_COLORS.get(risk_label, '#6B7280')}; border: 1px solid {RISK_COLORS.get(risk_label, '#6B7280')}40">
        <span style="font-size:1.1rem;">&#9679;</span> {risk_label}
      </div>
      <div class="score-ring">
        Risk Score <strong style="color: {RISK_COLORS.get(risk_label, '#6B7280')}">{risk_score}</strong>/100
      </div>
    </div>
  </div>

  <div class="summary">
    <div class="card">
      <div class="card-value" style="color: {RISK_COLORS['MEDIUM'] if sub_count else RISK_COLORS['INFO']}">{sub_count}</div>
      <div class="card-label">Subdomains</div>
    </div>
    <div class="card">
      <div class="card-value" style="color: {RISK_COLORS['MEDIUM'] if port_count else RISK_COLORS['INFO']}">{port_count}</div>
      <div class="card-label">Open Ports</div>
    </div>
    <div class="card">
      <div class="card-value" style="color: {RISK_COLORS['CRITICAL'] if breach_count else RISK_COLORS['CLEAN']}">{breach_count}</div>
      <div class="card-label">Breaches</div>
    </div>
    <div class="card">
      <div class="card-value" style="color: {RISK_COLORS['CRITICAL'] if vt_malicious else RISK_COLORS['CLEAN']}">{vt_malicious}</div>
      <div class="card-label">Malicious Flags</div>
    </div>
    <div class="card">
      <div class="card-value" style="color: {RISK_COLORS['HIGH'] if github_count else RISK_COLORS['CLEAN']}">{github_count}</div>
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
                html += f"<div class='record-line'><span class='tag tag-info'>{rtype}</span><span class='record-value'>{rec}</span></div>"
            html += "</div></details>"
    else:
        html += f"<div class='no-data'>{'No DNS records found' if not dns.get('error') else dns['error']}</div>"
    html += "</section>"

    # WHOIS section
    html += "<section><div class='section-title'>WHOIS Information</div>"
    if not whois.get("error"):
        items = [
            ("Registrar", whois.get("registrar")),
            ("Creation Date", whois.get("creation_date")),
            ("Expiration Date", whois.get("expiration_date")),
            ("Registrant Org", whois.get("registrant_org")),
        ]
        html += "<div class='whois-grid'>"
        for label, value in items:
            if value:
                html += f"<div class='whois-item'><div class='whois-label'>{label}</div><div class='whois-value'>{value}</div></div>"
        expiring_label = "Expiring Soon"
        expiring_value = "Yes" if whois.get("expiring_soon") else "No"
        expiring_cls = "inline-high" if whois.get("expiring_soon") else "inline-low"
        html += f"<div class='whois-item'><div class='whois-label'>{expiring_label}</div><div class='whois-value'><span class='inline-tag {expiring_cls}'>{expiring_value}</span></div></div>"
        html += "</div>"
        if whois.get("name_servers"):
            html += f"<details style='margin-top: 0.75rem;'><summary>Name Servers ({len(whois['name_servers'])})</summary><div class='content'>"
            for ns in whois["name_servers"]:
                html += f"<div style='font-size:0.8rem; font-family:SF Mono,Cascadia Code,JetBrains Mono,Consolas,monospace; padding:0.25rem 0; color:#9CA3AF;'>{ns}</div>"
            html += "</div></details>"
    else:
        html += f"<div class='no-data'>{whois['error']}</div>"
    html += "</section>"

    # Subdomains section
    html += "<section><div class='section-title'>Subdomain Enumeration</div>"
    live = subs.get("confirmed_live", [])
    if live:
        html += "<div class='table-wrap'><table><thead><tr><th>Subdomain</th><th>IP Addresses</th></tr></thead><tbody>"
        for s in live:
            ips = ", ".join(s.get("ips", []))
            html += f"<tr><td style='font-family:SF Mono,Cascadia Code,JetBrains Mono,Consolas,monospace;'>{s['subdomain']}</td><td>{ips}</td></tr>"
        html += "</tbody></table></div>"
    else:
        html += f"<div class='no-data'>No live subdomains discovered</div>"
    crt_count = subs.get("crt_sh_count", 0)
    brute_count = len(subs.get("bruteforce_found", []))
    html += f"<div class='sub-meta'>crt.sh: {crt_count} candidates &middot; Brute-force: {brute_count} resolved</div>"
    html += "</section>"

    # Shodan section
    html += "<section><div class='section-title'>Shodan — Open Ports &amp; Services</div>"
    if shodan_data.get("api_key_missing"):
        html += f"<div class='no-data'>Shodan API key not configured</div>"
    elif shodan_data.get("error"):
        html += f"<div class='no-data'>{shodan_data['error']}</div>"
    elif shodan_data.get("services"):
        html += "<div class='table-wrap'><table><thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Version</th></tr></thead><tbody>"
        for svc in shodan_data["services"]:
            html += f"<tr><td>{svc.get('port', '')}</td><td>{svc.get('protocol', '')}</td><td>{svc.get('service', '')}</td><td>{svc.get('product', '')}</td><td>{svc.get('version', '')}</td></tr>"
        html += "</tbody></table></div>"
        vulns = shodan_data.get("vulnerabilities", [])
        if vulns:
            html += "<div class='cve-list'>"
            for v in vulns:
                html += f"<span class='cve-item'>{v}</span>"
            html += "</div>"
    else:
        html += "<div class='no-data'>No services discovered</div>"
    html += "</section>"

    # HIBP section
    html += "<section><div class='section-title'>HaveIBeenPwned — Breach Check</div>"
    if hibp_data.get("api_key_missing"):
        html += f"<div class='no-data'>HIBP API key not configured</div>"
    elif hibp_data.get("breaches"):
        html += "<div class='table-wrap'><table><thead><tr><th>Breach Name</th><th>Domain</th><th>Date</th><th>Data Classes</th></tr></thead><tbody>"
        for b in hibp_data["breaches"]:
            classes = ", ".join(b.get("data_classes", []))
            html += f"<tr><td><strong>{b.get('name', '')}</strong></td><td>{b.get('domain', '')}</td><td>{b.get('date', '')}</td><td style='font-size: 0.7rem;'>{classes}</td></tr>"
        html += "</tbody></table></div>"
    else:
        html += f"<div class='no-data'>No breaches detected for common email patterns</div>"
    html += "</section>"

    # GitHub Dorks section
    html += "<section><div class='section-title'>GitHub Dorking</div>"
    if github_data.get("results"):
        html += "<div class='table-wrap'><table><thead><tr><th>Keyword</th><th>Repository</th><th>File</th></tr></thead><tbody>"
        for item in github_data["results"]:
            repo = item.get("repository", "")
            file_url = item.get("url", "")
            file_name = item.get("file", "")
            kw = item.get("keyword", "")
            if item.get("error") == "Rate limited":
                html += f"<tr><td><span class='inline-tag inline-medium'>{kw}</span></td><td colspan='2'><span style='color:#FBBF24;'>Rate limited — add GitHub token</span></td></tr>"
            else:
                html += f"<tr><td><span class='inline-tag inline-medium'>{kw}</span></td><td style='font-size:0.75rem;'>{repo}</td><td><a href='{file_url}' target='_blank'>{file_name}</a></td></tr>"
        html += "</tbody></table></div>"
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
        risk_color = RISK_COLORS.get(risk, "#6B7280")
        html += f"""
        <div class='vt-stats'>
          <div class='vt-stat'><div class='vt-stat-value' style='color:{risk_color};'>{risk}</div><div class='vt-stat-label'>Risk Level</div></div>
          <div class='vt-stat'><div class='vt-stat-value' style='color:#FCA5A5;'>{vt_data.get('malicious_count', 0)}</div><div class='vt-stat-label'>Malicious</div></div>
          <div class='vt-stat'><div class='vt-stat-value' style='color:#FDE047;'>{vt_data.get('suspicious_count', 0)}</div><div class='vt-stat-label'>Suspicious</div></div>
          <div class='vt-stat'><div class='vt-stat-value' style='color:#86EFAC;'>{vt_data.get('harmless_count', 0)}</div><div class='vt-stat-label'>Harmless</div></div>
        </div>"""
        if vt_data.get("categories"):
            cats = "<br>".join([f"<strong style='color:#A5B4FC;'>{k}:</strong> <span style='color:#9CA3AF;'>{v}</span>" for k, v in vt_data["categories"].items()])
            html += f"<div style='margin-top:0.75rem; font-size:0.8rem; line-height:1.8;'>{cats}</div>"
    html += "</section>"

    # Footer
    html += f"""
  <div class='footer'>
    Generated by <strong>GhostRecon v1.0</strong> &middot; <strong>GhostChain</strong> Project<br>
    Passive OSINT Reconnaissance Engine &mdash; Ethical Use Only
  </div>
  <div class='disclaimer'>
    <strong>&#9888; Legal Notice</strong><br>
    This report was generated for authorized security assessment purposes only.<br>
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
