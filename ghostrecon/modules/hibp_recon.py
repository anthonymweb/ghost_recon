import requests
from typing import Dict, Any, List, Optional

COMMON_EMAILS = ["admin", "info", "contact", "support", "noreply", "hello"]


def run(domain: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    result = {
        "domain": domain,
        "emails_checked": [],
        "breaches": [],
        "total_breaches": 0,
        "error": None,
        "api_key_missing": False,
    }

    if not api_key:
        result["api_key_missing"] = True
        result["error"] = "HIBP API key not configured. Skipping."
        return result

    emails = [f"{prefix}@{domain}" for prefix in COMMON_EMAILS]
    result["emails_checked"] = emails

    for email in emails:
        breaches = _check_email(email, api_key)
        for b in breaches:
            if b not in result["breaches"]:
                result["breaches"].append(b)

    result["total_breaches"] = len(result["breaches"])
    return result


def _check_email(email: str, api_key: str) -> List[Dict[str, Any]]:
    breaches = []
    try:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {
            "hibp-api-key": api_key,
            "User-Agent": "GhostRecon/1.0",
        }
        resp = requests.get(url, headers=headers, timeout=15)

        if resp.status_code == 200:
            for entry in resp.json():
                breaches.append({
                    "name": entry.get("Name", "Unknown"),
                    "domain": entry.get("Domain", ""),
                    "date": entry.get("BreachDate", ""),
                    "data_classes": entry.get("DataClasses", []),
                    "description": entry.get("Description", "")[:200],
                })
        elif resp.status_code == 404:
            pass
        elif resp.status_code == 429:
            pass
    except requests.RequestException:
        pass
    except ValueError:
        pass

    return breaches
