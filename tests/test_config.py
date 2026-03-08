"""Tests for trace_sanitizer.config — config persistence."""

import json
import stat

import pytest

from trace_sanitizer.config import load_config, save_config


class TestLoadConfig:
    def test_no_file_returns_defaults(self, tmp_config):
        config = load_config()
        assert config["excluded_projects"] == []
        assert config["redact_strings"] == []

    def test_valid_file_merged(self, tmp_config):
        tmp_config.parent.mkdir(parents=True, exist_ok=True)
        tmp_config.write_text(json.dumps({"source": "claude", "custom_key": "val"}))
        config = load_config()
        assert config["source"] == "claude"
        assert config["custom_key"] == "val"
        # Defaults still present
        assert "excluded_projects" in config

    def test_corrupt_json_returns_defaults(self, tmp_config, capsys):
        tmp_config.parent.mkdir(parents=True, exist_ok=True)
        tmp_config.write_text("not valid json {{{")
        config = load_config()
        assert config["source"] is None
        captured = capsys.readouterr()
        assert "Warning" in captured.err

    def test_extra_keys_preserved(self, tmp_config):
        tmp_config.parent.mkdir(parents=True, exist_ok=True)
        tmp_config.write_text(json.dumps({"source": None, "my_extra": [1, 2, 3]}))
        config = load_config()
        assert config["my_extra"] == [1, 2, 3]


class TestSaveConfig:
    def test_creates_dir_and_writes(self, tmp_config):
        save_config({"source": "claude", "excluded_projects": []})
        assert tmp_config.exists()
        data = json.loads(tmp_config.read_text())
        assert data["source"] == "claude"

    def test_overwrites_existing(self, tmp_config):
        tmp_config.parent.mkdir(parents=True, exist_ok=True)
        tmp_config.write_text(json.dumps({"source": "claude"}))
        save_config({"source": "codex"})
        data = json.loads(tmp_config.read_text())
        assert data["source"] == "codex"

    def test_sets_0600_permissions(self, tmp_config):
        save_config({"source": "claude"})
        mode = tmp_config.stat().st_mode
        assert stat.S_IMODE(mode) == 0o600

    def test_oserror_prints_warning(self, tmp_config, monkeypatch, capsys):
        # Make the directory unwritable
        monkeypatch.setattr(
            "trace_sanitizer.config.CONFIG_DIR",
            tmp_config.parent / "nonexistent" / "deep" / "dir",
        )
        # Actually mock mkdir to raise
        import trace_sanitizer.config as config_mod
        original_mkdir = type(tmp_config.parent).mkdir

        def failing_mkdir(self, *a, **kw):
            raise OSError("Permission denied")

        monkeypatch.setattr(type(tmp_config.parent), "mkdir", failing_mkdir)
        save_config({"source": "test"})
        captured = capsys.readouterr()
        assert "Warning" in captured.err
