import socket
from typing import Dict, Any, Optional


def run(domain: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    result = {
        "domain": domain,
        "ip": None,
        "ports": [],
        "services": [],
        "vulnerabilities": [],
        "error": None,
        "api_key_missing": False,
    }

    if not api_key:
        result["api_key_missing"] = True
        result["error"] = "Shodan API key not configured. Skipping."
        return result

    try:
        import shodan
    except ImportError:
        result["error"] = "shodan library not installed"
        return result

    try:
        ip = socket.gethostbyname(domain)
        result["ip"] = ip

        api = shodan.Shodan(api_key)
        host = api.host(ip)

        for service in host.get("data", []):
            port = service.get("port")
            transport = service.get("transport", "tcp")
            product = service.get("product", "")
            version = service.get("version", "")

            banner = service.get("data", "")
            if banner:
                banner = banner[:200]

            service_info = {
                "port": port,
                "protocol": f"{transport.upper()}",
                "service": service.get("_shodan", {}).get("module", ""),
                "product": product,
                "version": version,
                "banner": banner,
            }
            result["ports"].append(port)
            result["services"].append(service_info)

            vulns = service.get("vulns", {})
            if isinstance(vulns, dict):
                for cve in vulns.keys():
                    if cve not in result["vulnerabilities"]:
                        result["vulnerabilities"].append(cve)

    except shodan.exception.APIError as e:
        if "Invalid API key" in str(e):
            result["error"] = "Invalid Shodan API key"
        elif "limit" in str(e).lower():
            result["error"] = "Shodan API query limit reached"
        else:
            result["error"] = f"Shodan API error: {str(e)}"
    except socket.gaierror:
        result["error"] = f"Could not resolve {domain} to IP"
    except Exception as e:
        result["error"] = f"Shodan lookup failed: {str(e)}"

    return result
