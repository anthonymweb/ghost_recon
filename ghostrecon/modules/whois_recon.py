import whois
from datetime import datetime, timezone
from typing import Dict, Any


def run(domain: str) -> Dict[str, Any]:
    result = {
        "domain": domain,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "name_servers": [],
        "registrant_org": None,
        "expiring_soon": False,
        "error": None,
    }

    try:
        w = whois.whois(domain)

        result["registrar"] = _clean(w.registrar)
        result["creation_date"] = _clean_date(w.creation_date)
        result["expiration_date"] = _clean_date(w.expiration_date)
        result["name_servers"] = _clean_list(w.name_servers)
        result["registrant_org"] = _clean(w.org)

        if result["expiration_date"]:
            try:
                exp = result["expiration_date"]
                if isinstance(exp, str):
                    exp = datetime.fromisoformat(exp.replace("Z", "+00:00"))
                if isinstance(exp, datetime):
                    if exp.tzinfo is None:
                        exp = exp.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_left = (exp - now).days
                    result["expiring_soon"] = 0 <= days_left <= 90
            except Exception:
                pass

    except whois.parser.PywhoisError as e:
        if "No match for" in str(e) or "NOT FOUND" in str(e):
            result["error"] = f"Domain {domain} not found in WHOIS"
        else:
            result["error"] = f"WHOIS parse error: {str(e)}"
    except Exception as e:
        result["error"] = f"WHOIS lookup failed: {str(e)}"

    return result


def _clean(val):
    if isinstance(val, list):
        return str(val[0]) if val else None
    return str(val) if val else None


def _clean_date(val):
    if not val:
        return None
    if isinstance(val, list):
        val = val[0]
    if isinstance(val, datetime):
        return val.isoformat()
    return str(val)


def _clean_list(val):
    if not val:
        return []
    if isinstance(val, str):
        return [val]
    return [str(v) for v in val if v]
