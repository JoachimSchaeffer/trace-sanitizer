"""Persistent config for trace-sanitizer — stored at ~/.trace-sanitizer/config.json"""

import json
import os
import sys
from pathlib import Path
from typing import TypedDict, cast

CONFIG_DIR = Path.home() / ".trace-sanitizer"
CONFIG_FILE = CONFIG_DIR / "config.json"


class TraceSanitizerConfig(TypedDict, total=False):
    """Expected shape of the config dict."""

    source: str | None  # "claude" | "codex" | "gemini" | "all"
    excluded_projects: list[str]
    redact_strings: list[str]
    redact_usernames: list[str]
    last_export: dict
    stage: str | None  # "configure" | "review" | "confirmed"
    projects_confirmed: bool  # True once user has addressed folder exclusions
    include_tool_outputs: bool | None  # True to include tool outputs in export
    review_attestations: dict
    review_verification: dict
    last_confirm: dict
    publish_attestation: str


DEFAULT_CONFIG: TraceSanitizerConfig = {
    "source": None,
    "excluded_projects": [],
    "redact_strings": [],
}


def load_config() -> TraceSanitizerConfig:
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE) as f:
                stored = json.load(f)
            return cast(TraceSanitizerConfig, {**DEFAULT_CONFIG, **stored})
        except (json.JSONDecodeError, OSError) as e:
            print(f"Warning: could not read {CONFIG_FILE}: {e}", file=sys.stderr)
    return cast(TraceSanitizerConfig, dict(DEFAULT_CONFIG))


def save_config(config: TraceSanitizerConfig) -> None:
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Create file with 0600 from the start to avoid TOCTOU race
        fd = os.open(str(CONFIG_FILE), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(config, f, indent=2)
    except OSError as e:
        print(f"Warning: could not save {CONFIG_FILE}: {e}", file=sys.stderr)
