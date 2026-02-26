"""Anonymize PII in Claude Code log data."""

import hashlib
import os
import re


def _hash_username(username: str) -> str:
    return "user_" + hashlib.sha256(username.encode()).hexdigest()[:8]


def _detect_home_dir() -> tuple[str, str]:
    home = os.path.expanduser("~")
    username = os.path.basename(home)
    return home, username


def anonymize_path(path: str, username: str, username_hash: str, home: str | None = None) -> str:
    """Strip a path to project-relative and hash the username."""
    if not path:
        return path

    if home is None:
        home = os.path.expanduser("~")
    prefixes = set()
    for base in (f"/Users/{username}", f"/home/{username}", home):
        for subdir in ("Documents", "Downloads", "Desktop"):
            prefixes.add(f"{base}/{subdir}/")
        prefixes.add(f"{base}/")

    # Try longest prefixes first (subdirectory matches before bare home)
    home_patterns = sorted(prefixes, key=len, reverse=True)

    for prefix in home_patterns:
        if path.startswith(prefix):
            rest = path[len(prefix):]
            if "/Documents/" in prefix or "/Downloads/" in prefix or "/Desktop/" in prefix:
                return rest
            return f"{username_hash}/{rest}"

    path = path.replace(f"/Users/{username}/", f"/{username_hash}/")
    path = path.replace(f"/home/{username}/", f"/{username_hash}/")

    return path


def anonymize_text(text: str, username: str, username_hash: str) -> str:
    if not text or not username:
        return text

    escaped = re.escape(username)

    # Replace /Users/<username> and /home/<username>
    text = re.sub(rf"/Users/{escaped}(?=/|[^a-zA-Z0-9_-]|$)", f"/{username_hash}", text)
    text = re.sub(rf"/home/{escaped}(?=/|[^a-zA-Z0-9_-]|$)", f"/{username_hash}", text)

    # Catch hyphen-encoded paths: -Users-peteromalley- or -Users-peteromalley/
    text = re.sub(rf"-Users-{escaped}(?=-|/|$)", f"-Users-{username_hash}", text)
    text = re.sub(rf"-home-{escaped}(?=-|/|$)", f"-home-{username_hash}", text)

    # Catch temp paths like /private/tmp/claude-501/-Users-peteromalley/
    text = re.sub(rf"claude-\d+/-Users-{escaped}", f"claude-XXX/-Users-{username_hash}", text)

    # Final pass: replace bare username in remaining contexts (ls output, prose, etc.)
    # Only if username is >= 4 chars to avoid false positives
    if len(username) >= 4:
        text = re.sub(rf"\b{escaped}\b", username_hash, text)

    return text


class Anonymizer:
    """Stateful anonymizer that consistently hashes usernames."""

    def __init__(self, extra_usernames: list[str] | None = None):
        self.home, self.username = _detect_home_dir()
        self.username_hash = _hash_username(self.username)

        # Additional usernames to anonymize (GitHub handles, Discord names, etc.)
        self._extra: list[tuple[str, str]] = []
        for name in (extra_usernames or []):
            name = name.strip()
            if name and name != self.username:
                self._extra.append((name, _hash_username(name)))

    def path(self, file_path: str) -> str:
        result = anonymize_path(file_path, self.username, self.username_hash, self.home)
        result = anonymize_text(result, self.username, self.username_hash)
        for name, hashed in self._extra:
            result = _replace_username(result, name, hashed)
        return result

    def text(self, content: str) -> str:
        result = anonymize_text(content, self.username, self.username_hash)
        for name, hashed in self._extra:
            result = _replace_username(result, name, hashed)
        return result


def _replace_username(text: str, username: str, username_hash: str) -> str:
    if not text or not username or len(username) < 3:
        return text
    escaped = re.escape(username)
    text = re.sub(escaped, username_hash, text, flags=re.IGNORECASE)
    return text
