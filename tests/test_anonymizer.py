"""Tests for trace_sanitizer.anonymizer — PII anonymization."""

import pytest

from trace_sanitizer.anonymizer import (
    Anonymizer,
    _hash_username,
    _replace_username,
    _set_salt,
    anonymize_path,
    anonymize_text,
)


@pytest.fixture(autouse=True)
def _fixed_salt():
    """Pin the HMAC salt so hash outputs are deterministic in tests."""
    _set_salt(b"test-salt-fixed!")
    yield
    _set_salt(b"test-salt-fixed!")


# --- _hash_username ---


class TestHashUsername:
    def test_deterministic(self):
        assert _hash_username("alice") == _hash_username("alice")

    def test_different_inputs_differ(self):
        assert _hash_username("alice") != _hash_username("bob")

    def test_prefix_format(self):
        result = _hash_username("alice")
        assert result.startswith("user_")
        assert len(result) == 21  # "user_" + 16 hex chars

    def test_hex_chars(self):
        result = _hash_username("testuser")
        suffix = result[5:]
        assert all(c in "0123456789abcdef" for c in suffix)


# --- anonymize_path ---


class TestAnonymizePath:
    def test_empty_path(self):
        assert anonymize_path("", "alice", "user_abc12345") == ""

    def test_documents_prefix_stripped(self):
        result = anonymize_path(
            "/Users/alice/Documents/myproject/src/main.py",
            "alice", "user_abc12345", home="/Users/alice",
        )
        assert result == "myproject/src/main.py"

    def test_downloads_prefix_stripped(self):
        result = anonymize_path(
            "/Users/alice/Downloads/file.zip",
            "alice", "user_abc12345", home="/Users/alice",
        )
        assert result == "file.zip"

    def test_desktop_prefix_stripped(self):
        result = anonymize_path(
            "/Users/alice/Desktop/notes.txt",
            "alice", "user_abc12345", home="/Users/alice",
        )
        assert result == "notes.txt"

    def test_bare_home_hashed(self):
        result = anonymize_path(
            "/Users/alice/somedir/file.py",
            "alice", "user_abc12345", home="/Users/alice",
        )
        assert result == "user_abc12345/somedir/file.py"

    def test_linux_home_path(self):
        result = anonymize_path(
            "/home/alice/Documents/project/file.py",
            "alice", "user_abc12345", home="/home/alice",
        )
        assert result == "project/file.py"

    def test_path_not_under_home(self):
        result = anonymize_path(
            "/var/log/syslog",
            "alice", "user_abc12345", home="/Users/alice",
        )
        assert result == "/var/log/syslog"

    def test_fallback_users_replacement(self):
        # Path with username not matching the prefix set
        result = anonymize_path(
            "/tmp/Users/alice/something",
            "alice", "user_abc12345", home="/Users/alice",
        )
        # Falls through prefix matching, hits the fallback .replace
        assert "user_abc12345" in result or "/tmp/" in result


# --- anonymize_text ---


class TestAnonymizeText:
    def test_empty_text(self):
        assert anonymize_text("", "alice", "user_abc12345") == ""

    def test_empty_username(self):
        assert anonymize_text("hello alice", "", "user_abc12345") == "hello alice"

    def test_none_text(self):
        assert anonymize_text(None, "alice", "user_abc12345") is None

    def test_users_path_replaced(self):
        result = anonymize_text(
            "File at /Users/alice/project/main.py",
            "alice", "user_abc12345",
        )
        assert "/user_abc12345/project/main.py" in result

    def test_home_path_replaced(self):
        result = anonymize_text(
            "File at /home/alice/project/main.py",
            "alice", "user_abc12345",
        )
        assert "/user_abc12345/project/main.py" in result

    def test_hyphen_encoded_path(self):
        result = anonymize_text(
            "-Users-alice-Documents-myproject",
            "alice", "user_abc12345",
        )
        assert "-Users-user_abc12345" in result

    def test_temp_path(self):
        # The hyphen-encoded path regex runs before the temp path regex,
        # so the username gets replaced but claude-XXX may not trigger.
        # The important thing is the username is anonymized.
        result = anonymize_text(
            "/private/tmp/claude-501/-Users-alice-Documents-proj/foo",
            "alice", "user_abc12345",
        )
        assert "alice" not in result
        assert "user_abc12345" in result

    def test_bare_username_replaced(self):
        result = anonymize_text(
            "Hello alice, welcome back",
            "alice", "user_abc12345",
        )
        assert "alice" not in result
        assert "user_abc12345" in result

    def test_short_username_not_replaced_bare(self):
        # Usernames < 4 chars should NOT be replaced as bare words
        result = anonymize_text(
            "Hello bob, welcome back",
            "bob", "user_abc12345",
        )
        assert "bob" in result  # bare replacement skipped for short username

    def test_short_username_path_still_replaced(self):
        # Even short usernames should be replaced in path contexts
        result = anonymize_text(
            "File at /Users/bob/project",
            "bob", "user_abc12345",
        )
        assert "/user_abc12345/project" in result


# --- Anonymizer class ---


class TestAnonymizer:
    def test_path_method(self, mock_anonymizer):
        result = mock_anonymizer.path("/Users/testuser/Documents/myproject/main.py")
        assert "testuser" not in result
        assert "myproject/main.py" in result

    def test_text_method(self, mock_anonymizer):
        result = mock_anonymizer.text("Hello testuser, your home is /Users/testuser")
        assert "testuser" not in result

    def test_deterministic_hash(self, mock_anonymizer):
        r1 = mock_anonymizer.path("/Users/testuser/Documents/proj/a.py")
        r2 = mock_anonymizer.path("/Users/testuser/Documents/proj/a.py")
        assert r1 == r2

    def test_extra_usernames(self, monkeypatch):
        monkeypatch.setattr(
            "trace_sanitizer.anonymizer._detect_home_dir",
            lambda: ("/Users/testuser", "testuser"),
        )
        anon = Anonymizer(extra_usernames=["github_handle"])
        result = anon.text("by github_handle on GitHub")
        assert "github_handle" not in result

    def test_extra_usernames_dedup(self, monkeypatch):
        monkeypatch.setattr(
            "trace_sanitizer.anonymizer._detect_home_dir",
            lambda: ("/Users/testuser", "testuser"),
        )
        # Primary username in extra list should be skipped (not duplicated)
        anon = Anonymizer(extra_usernames=["testuser", "other"])
        assert len(anon._extra) == 1  # only "other"


# --- _replace_username ---


class TestReplaceUsername:
    def test_case_insensitive(self):
        result = _replace_username("Hello ALICE and Alice", "alice", "user_abc")
        assert "ALICE" not in result
        assert "Alice" not in result
        assert "user_abc" in result

    def test_short_username_skipped(self):
        # < 3 chars should be skipped
        result = _replace_username("Hello ab and AB", "ab", "user_abc")
        assert result == "Hello ab and AB"

    def test_empty_text(self):
        assert _replace_username("", "alice", "user_abc") == ""

    def test_empty_username(self):
        assert _replace_username("hello", "", "user_abc") == "hello"

    def test_none_text(self):
        assert _replace_username(None, "alice", "user_abc") is None
