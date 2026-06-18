import os
import sys
import json
import yaml
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime
import threading

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from output.report_generator import generate
from modules import dns_recon, whois_recon, subdomain_recon, shodan_recon, hibp_recon, github_dorks, virustotal_recon

BASE = Path(__file__).resolve().parent
STATIC = BASE / "static"
REPORTS_DIR = BASE.parent / "reports"
CONFIG_PATH = BASE.parent / "config.yaml"

HTML = (STATIC / "index.html").read_text(encoding="utf-8") if (STATIC / "index.html").exists() else ""


def load_config():
    config = {"api_keys": {"shodan": "", "virustotal": "", "hibp": "", "github": ""}}
    if CONFIG_PATH.exists():
        try:
            loaded = yaml.safe_load(CONFIG_PATH.read_text()) or {}
            if "api_keys" in loaded:
                config["api_keys"].update(loaded["api_keys"])
        except Exception:
            pass
    return config


def save_config(api_keys: dict):
    config = load_config()
    config["api_keys"].update(api_keys)
    CONFIG_PATH.write_text(yaml.dump(config, default_flow_style=False))


def run_scan(target: str, modules: list[str], api_keys: dict) -> dict:
    results = {}
    module_map = {
        "dns": lambda: dns_recon.run(target),
        "whois": lambda: whois_recon.run(target),
        "subdomains": lambda: subdomain_recon.run(target),
        "shodan": lambda: shodan_recon.run(target, api_key=api_keys.get("shodan")),
        "hibp": lambda: hibp_recon.run(target, api_key=api_keys.get("hibp")),
        "github": lambda: github_dorks.run(target, token=api_keys.get("github")),
        "virustotal": lambda: virustotal_recon.run(target, api_key=api_keys.get("virustotal")),
    }
    for mod in modules:
        if mod in module_map:
            try:
                results[mod] = module_map[mod]()
            except Exception as e:
                results[mod] = {"error": str(e)}
    return results


class Handler(BaseHTTPRequestHandler):

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _send_html(self, html, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())

    def _send_file(self, path):
        ext = path.suffix.lower()
        types = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css",
            ".js": "application/javascript",
            ".png": "image/png",
            ".svg": "image/svg+xml",
            ".ico": "image/x-icon",
        }
        ctype = types.get(ext, "application/octet-stream")
        try:
            data = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(data)
        except FileNotFoundError:
            self._send_json({"error": "Not found"}, 404)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/":
            self._send_html(HTML)
        elif path == "/api/config":
            self._send_json(load_config())
        elif path.startswith("/reports/"):
            filename = path.replace("/reports/", "")
            filepath = REPORTS_DIR / filename
            if filepath.exists():
                self._send_file(filepath)
            else:
                self._send_json({"error": "Report not found"}, 404)
        else:
            static_path = STATIC / path.lstrip("/")
            if static_path.exists() and static_path.is_file():
                self._send_file(static_path)
            else:
                self._send_json({"error": "Not found"}, 404)

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode() if content_len else "{}"
        data = json.loads(body) if body else {}

        parsed = urlparse(self.path)

        if parsed.path == "/api/scan":
            target = data.get("target", "").strip().lower()
            if not target:
                self._send_json({"error": "Target is required"}, 400)
                return

            modules = data.get("modules", ["dns", "whois", "subdomains", "shodan", "hibp", "github", "virustotal"])
            api_keys = data.get("api_keys", {})

            save_config(api_keys)

            def scan_and_respond():
                results = run_scan(target, modules, api_keys)
                try:
                    report_path = generate(results, target)
                    report_name = Path(report_path).name
                    self._send_json({
                        "status": "complete",
                        "results": results,
                        "report": f"/reports/{report_name}",
                    })
                except Exception as e:
                    self._send_json({
                        "status": "error",
                        "error": str(e),
                        "results": results,
                    }, 500)

            thread = threading.Thread(target=scan_and_respond, daemon=True)
            thread.start()
            thread.join()

        elif parsed.path == "/api/config":
            api_keys = data.get("api_keys", {})
            save_config(api_keys)
            self._send_json({"status": "saved", "config": load_config()})

        else:
            self._send_json({"error": "Not found"}, 404)

    def log_message(self, format, *args):
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = HTTPServer(("0.0.0.0", port), Handler)
    print(f"\n  GhostRecon Web UI → http://localhost:{port}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
