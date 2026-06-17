import dns.resolver
import dns.exception
import requests
from typing import Dict, Any, List

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "test", "stage", "blog",
    "shop", "store", "app", "m", "mobile", "webmail", "smtp", "pop3",
    "imap", "vpn", "remote", "portal", "secure", "login", "auth", "sso",
    "cdn", "static", "assets", "img", "css", "js", "media", "upload",
    "download", "docs", "wiki", "kb", "help", "support", "status",
    "statuspage", "community", "forum", "chat", "discuss", "news",
    "events", "calendar", "jobs", "careers", "hr", "intranet",
    "internal", "corp", "office", "server", "db", "database", "sql",
    "redis", "cache", "proxy", "gateway", "router", "switch", "ns1",
    "ns2", "ns3", "ns4", "dns", "dns1", "dns2", "mx", "mx1", "mx2",
    "mail1", "mail2", "web", "www2", "www3", "home", "info", "en",
    "fr", "de", "es", "pt", "jp", "cn", "ru", "it", "nl", "pl",
    "tr", "br", "mx", "au", "in", "co", "uk", "ca",
]


def run(domain: str) -> Dict[str, Any]:
    result = {
        "domain": domain,
        "crt_sh_count": 0,
        "crt_sh_subdomains": [],
        "bruteforce_found": [],
        "confirmed_live": [],
        "error": None,
    }

    crt_subdomains = _query_crtsh(domain)
    result["crt_sh_subdomains"] = crt_subdomains
    result["crt_sh_count"] = len(crt_subdomains)

    brute_subdomains = _bruteforce_subdomains(domain)
    result["bruteforce_found"] = brute_subdomains

    all_subdomains = list(set(crt_subdomains + brute_subdomains))
    live = _resolve_subdomains(domain, all_subdomains)

    result["confirmed_live"] = live

    return result


def _query_crtsh(domain: str) -> List[str]:
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = requests.get(url, timeout=15, headers={"User-Agent": "GhostRecon/1.0"})
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name = entry.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lower()
                    if n.endswith(f".{domain}") and n != f"*.{domain}":
                        subdomains.add(n)
    except requests.RequestException:
        pass
    except ValueError:
        pass
    return sorted(subdomains)


def _bruteforce_subdomains(domain: str) -> List[str]:
    found = []
    for sub in COMMON_SUBDOMAINS:
        fqdn = f"{sub}.{domain}"
        try:
            answers = dns.resolver.resolve(fqdn, "A", lifetime=3)
            if answers:
                found.append(fqdn)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            continue
        except Exception:
            continue
    return found


def _resolve_subdomains(domain: str, subdomains: List[str]) -> List[Dict[str, Any]]:
    live = []
    for sd in subdomains:
        ips = []
        try:
            answers = dns.resolver.resolve(sd, "A", lifetime=3)
            ips = [str(r) for r in answers]
        except Exception:
            continue
        live.append({
            "subdomain": sd,
            "ips": ips,
        })
    return live
