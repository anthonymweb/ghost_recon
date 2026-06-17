import dns.resolver
import dns.exception
from typing import Dict, List, Any

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def run(domain: str) -> Dict[str, Any]:
    results = {
        "domain": domain,
        "records": {},
        "error": None,
    }

    for rtype in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, rtype, raise_on_no_answer=False)
            records = []
            for rdata in answers:
                if rtype == "MX":
                    records.append(f"{rdata.preference} {rdata.exchange}")
                elif rtype == "SOA":
                    records.append(f"{rdata.mname} {rdata.rname} (serial: {rdata.serial})")
                elif rtype == "TXT":
                    txt_parts = [s.decode() if isinstance(s, bytes) else str(s) for s in rdata.strings]
                    records.append("".join(txt_parts))
                else:
                    records.append(str(rdata))

            if records:
                results["records"][rtype] = records

        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            results["error"] = f"Domain {domain} does not exist (NXDOMAIN)"
            return results
        except dns.exception.Timeout:
            results["records"][rtype] = ["[TIMEOUT]"]
        except Exception as e:
            results["records"][rtype] = [f"[ERROR] {str(e)}"]

    return results
