import requests
from typing import Dict, Any, Optional


def run(domain: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    result = {
        "domain": domain,
        "reputation_score": None,
        "malicious_count": 0,
        "suspicious_count": 0,
        "harmless_count": 0,
        "undetected_count": 0,
        "categories": {},
        "risk_level": "UNKNOWN",
        "error": None,
        "api_key_missing": False,
    }

    if not api_key:
        result["api_key_missing"] = True
        result["error"] = "VirusTotal API key not configured. Skipping."
        return result

    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": api_key, "Accept": "application/json"}
        resp = requests.get(url, headers=headers, timeout=15)

        if resp.status_code == 200:
            data = resp.json()
            attributes = data.get("data", {}).get("attributes", {})

            last_analysis_stats = attributes.get("last_analysis_stats", {})
            result["malicious_count"] = last_analysis_stats.get("malicious", 0)
            result["suspicious_count"] = last_analysis_stats.get("suspicious", 0)
            result["harmless_count"] = last_analysis_stats.get("harmless", 0)
            result["undetected_count"] = last_analysis_stats.get("undetected", 0)

            result["reputation_score"] = attributes.get("reputation")
            result["categories"] = attributes.get("categories", {})

            malicious = result["malicious_count"]
            suspicious = result["suspicious_count"]
            if malicious >= 5:
                result["risk_level"] = "MALICIOUS"
            elif malicious >= 1:
                result["risk_level"] = "SUSPICIOUS"
            elif suspicious >= 2:
                result["risk_level"] = "SUSPICIOUS"
            elif suspicious == 0 and malicious == 0:
                result["risk_level"] = "CLEAN"
            else:
                result["risk_level"] = "CLEAN"

        elif resp.status_code == 404:
            result["error"] = f"Domain {domain} not found in VirusTotal"
        else:
            result["error"] = f"VirusTotal API returned status {resp.status_code}"

    except requests.RequestException as e:
        result["error"] = f"VirusTotal request failed: {str(e)}"

    return result
