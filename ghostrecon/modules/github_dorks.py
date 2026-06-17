import requests
import time
from typing import Dict, Any, List, Optional

DORK_QUERIES = [
    "password",
    "secret",
    "api_key",
    "token",
    "credentials",
    ".env",
    "config",
    "database",
    "connection_string",
    "ssh",
    "private_key",
    "aws_key",
    "slack_token",
    "firebase",
    "auth_token",
    "bearer",
    "jwt_secret",
    "client_secret",
]


def run(domain: str, token: Optional[str] = None) -> Dict[str, Any]:
    result = {
        "domain": domain,
        "results": [],
        "total_findings": 0,
        "error": None,
    }

    for query in DORK_QUERIES:
        findings = _search_github(domain, query, token)
        result["results"].extend(findings)
        time.sleep(0.3)

    result["total_findings"] = len(result["results"])
    return result


def _search_github(domain: str, keyword: str, token: Optional[str] = None) -> List[Dict[str, Any]]:
    findings = []
    try:
        query = f'"{domain}" {keyword}'
        url = "https://api.github.com/search/code"
        headers = {"Accept": "application/vnd.github.v3+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        params = {"q": query, "per_page": 5}
        resp = requests.get(url, headers=headers, params=params, timeout=15)

        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("items", [])[:5]:
                findings.append({
                    "keyword": keyword,
                    "repository": item.get("repository", {}).get("full_name", ""),
                    "file": item.get("path", ""),
                    "url": item.get("html_url", ""),
                    "repo_url": item.get("repository", {}).get("html_url", ""),
                })
        elif resp.status_code == 403:
            if "rate limit" in resp.text.lower():
                result = {
                    "keyword": keyword,
                    "repository": "",
                    "file": "",
                    "url": "",
                    "repo_url": "",
                    "error": "Rate limited",
                }
                findings.append(result)

    except requests.RequestException:
        pass

    return findings
