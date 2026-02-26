"""Persistent config for safety-dataclaw — stored at ~/.safety-dataclaw/config.json"""

import json
import sys
from pathlib import Path
from typing import TypedDict, cast

CONFIG_DIR = Path.home() / ".safety-dataclaw"
CONFIG_FILE = CONFIG_DIR / "config.json"


class SafetyDataclawConfig(TypedDict, total=False):
    """Expected shape of the config dict."""

    api_key: str | None
    traced_url: str | None  # defaults to "https://traced.run"
    source: str | None  # "claude" | "codex" | "gemini" | "all"
    excluded_projects: list[str]
    redact_strings: list[str]
    redact_usernames: list[str]
    last_export: dict
    stage: str | None  # "auth" | "configure" | "review" | "confirmed" | "done"
    projects_confirmed: bool  # True once user has addressed folder exclusions
    review_attestations: dict
    review_verification: dict
    last_confirm: dict
    publish_attestation: str


DEFAULT_CONFIG: SafetyDataclawConfig = {
    "api_key": None,
    "traced_url": "https://traced.run",
    "source": None,
    "excluded_projects": [],
    "redact_strings": [],
}


def load_config() -> SafetyDataclawConfig:
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE) as f:
                stored = json.load(f)
            return cast(SafetyDataclawConfig, {**DEFAULT_CONFIG, **stored})
        except (json.JSONDecodeError, OSError) as e:
            print(f"Warning: could not read {CONFIG_FILE}: {e}", file=sys.stderr)
    return cast(SafetyDataclawConfig, dict(DEFAULT_CONFIG))


def save_config(config: SafetyDataclawConfig) -> None:
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=2)
        CONFIG_FILE.chmod(0o600)
    except OSError as e:
        print(f"Warning: could not save {CONFIG_FILE}: {e}", file=sys.stderr)
