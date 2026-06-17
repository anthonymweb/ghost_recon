#!/usr/bin/env python3
import sys
import click
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

sys.path.insert(0, str(Path(__file__).resolve().parent))

from utils.banner import print_banner
from utils.logger import log_success, log_warning, log_error, log_module_header, log_finding, console
from utils.config import get_api_key
from modules import dns_recon, whois_recon, subdomain_recon, shodan_recon, hibp_recon, github_dorks, virustotal_recon
from output.report_generator import generate


@click.command()
@click.option("-t", "--target", required=True, help="Target domain to scan")
@click.option("-o", "--output", default=None, help="Output filename for HTML report")
@click.option("-m", "--modules", default=None, help="Comma-separated modules to run (default: all)")
@click.option("--shodan-key", default=None, help="Shodan API key")
@click.option("--vt-key", default=None, help="VirusTotal API key")
@click.option("--hibp-key", default=None, help="HIBP API key")
@click.option("--github-key", default=None, help="GitHub personal access token")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
def main(target, output, modules, shodan_key, vt_key, hibp_key, github_key, verbose):
    print_banner()
    console.print(f"  [bold white]Target:[/bold white] [cyan]{target}[/cyan]")
    console.print(f"  [bold white]Started:[/bold white] [cyan]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/cyan]")
    console.print()

    results = {}
    module_map = {
        "dns": _run_dns,
        "whois": _run_whois,
        "subdomains": _run_subdomains,
        "shodan": _run_shodan,
        "hibp": _run_hibp,
        "github": _run_github,
        "virustotal": _run_virustotal,
    }

    selected = modules.split(",") if modules else list(module_map.keys())
    selected = [m.strip().lower() for m in selected]

    api_keys = {
        "shodan": get_api_key("shodan", shodan_key),
        "virustotal": get_api_key("virustotal", vt_key),
        "hibp": get_api_key("hibp", hibp_key),
        "github": get_api_key("github", github_key),
    }

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(style="purple", complete_style="cyan"),
        console=console,
    ) as progress:
        for mod_name in selected:
            if mod_name not in module_map:
                log_warning("SKIP", f"Unknown module: {mod_name}")
                continue

            task = progress.add_task(f"[cyan]{mod_name}[/cyan]", total=None)
            try:
                result = module_map[mod_name](target, api_keys)
                results[mod_name] = result
                _display_results(mod_name, result)
            except Exception as e:
                log_error(mod_name.upper(), str(e))
                results[mod_name] = {"error": str(e)}
            finally:
                progress.remove_task(task)

    report_path = generate(results, target, output)
    console.print()
    console.rule("[bold green] SCAN COMPLETE [/bold green]")
    console.print(f"  [green]Report saved:[/green] [bold cyan]{report_path}[/bold cyan]")
    console.print()


def _display_results(module: str, result: dict):
    if result.get("error"):
        log_error(module.upper(), result["error"])
        return

    if module == "dns":
        log_module_header("DNS Enumeration")
        records = result.get("records", {})
        for rtype, recs in records.items():
            for rec in recs:
                log_finding(rtype, rec)
        if not records:
            log_finding("INFO", "No DNS records found")

    elif module == "whois":
        log_module_header("WHOIS Lookup")
        log_finding("Registrar", result.get("registrar", "N/A"))
        log_finding("Created", result.get("creation_date", "N/A"))
        log_finding("Expires", result.get("expiration_date", "N/A"))
        log_finding("Organization", result.get("registrant_org", "N/A"))
        if result.get("expiring_soon"):
            log_finding("[!] EXPIRING SOON", "Domain expires within 90 days", "high")

    elif module == "subdomains":
        log_module_header("Subdomain Enumeration")
        live = result.get("confirmed_live", [])
        for s in live:
            log_finding(s["subdomain"], ", ".join(s.get("ips", [])), "info")
        log_success("SUBDOMAINS", f"{len(live)} live subdomains found")
        log_finding("crt.sh candidates", str(result.get("crt_sh_count", 0)), "low")
        log_finding("Brute-force resolved", str(len(result.get("bruteforce_found", []))), "low")

    elif module == "shodan":
        log_module_header("Shodan Reconnaissance")
        for svc in result.get("services", []):
            log_finding(f"Port {svc.get('port', '?')}/{svc.get('protocol', 'tcp')}",
                        f"{svc.get('service', '')} {svc.get('product', '')} {svc.get('version', '')}".strip())
        for cve in result.get("vulnerabilities", []):
            log_finding("CVE", cve, "critical")
        if not result.get("services"):
            log_finding("INFO", "No open ports discovered", "info")

    elif module == "hibp":
        log_module_header("HaveIBeenPwned — Breach Check")
        for b in result.get("breaches", []):
            log_finding(b.get("name", "?"), f"{b.get('date', '')} — {', '.join(b.get('data_classes', []))}", "critical")
        if result.get("total_breaches", 0) == 0:
            log_finding("CLEAN", "No breaches detected", "low")

    elif module == "github":
        log_module_header("GitHub Dorking")
        for item in result.get("results", []):
            if item.get("error") == "Rate limited":
                log_warning("GITHUB", "Rate limited — add GitHub token for full results")
            else:
                log_finding(item.get("keyword", "?"), item.get("url", ""), "medium")
        if result.get("total_findings", 0) == 0:
            log_finding("CLEAN", "No exposed secrets found", "low")

    elif module == "virustotal":
        log_module_header("VirusTotal — Domain Reputation")
        risk = result.get("risk_level", "UNKNOWN")
        sev = "critical" if risk == "MALICIOUS" else "medium" if risk == "SUSPICIOUS" else "low"
        log_finding("Risk Level", risk, sev)
        log_finding("Malicious", str(result.get("malicious_count", 0)), "critical")
        log_finding("Suspicious", str(result.get("suspicious_count", 0)), "medium")
        log_finding("Harmless", str(result.get("harmless_count", 0)), "low")


def _run_dns(target, api_keys):
    return dns_recon.run(target)


def _run_whois(target, api_keys):
    return whois_recon.run(target)


def _run_subdomains(target, api_keys):
    return subdomain_recon.run(target)


def _run_shodan(target, api_keys):
    return shodan_recon.run(target, api_key=api_keys.get("shodan"))


def _run_hibp(target, api_keys):
    return hibp_recon.run(target, api_key=api_keys.get("hibp"))


def _run_github(target, api_keys):
    return github_dorks.run(target, token=api_keys.get("github"))


def _run_virustotal(target, api_keys):
    return virustotal_recon.run(target, api_key=api_keys.get("virustotal"))


if __name__ == "__main__":
    main()
