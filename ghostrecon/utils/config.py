import os
import yaml
from pathlib import Path

CONFIG_PATHS = [
    Path("config.yaml"),
    Path.home() / ".config" / "ghostrecon" / "config.yaml",
    Path(os.getcwd()) / "config.yaml",
]


def load_config() -> dict:
    config = {"api_keys": {"shodan": "", "virustotal": "", "hibp": "", "github": ""}}

    for path in CONFIG_PATHS:
        if path.exists():
            try:
                with open(path) as f:
                    loaded = yaml.safe_load(f) or {}
                    if "api_keys" in loaded:
                        config["api_keys"].update(loaded["api_keys"])
                return config
            except Exception:
                continue

    return config


def get_api_key(key_name: str, cli_value: str | None = None) -> str:
    if cli_value:
        return cli_value
    config = load_config()
    return config.get("api_keys", {}).get(key_name, "")


def config_file_exists() -> bool:
    for path in CONFIG_PATHS:
        if path.exists():
            return True
    return False
