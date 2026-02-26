"""Tests for safety_dataclaw.cli — CLI commands and helpers."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from safety_dataclaw.cli import (
    _build_status_next_steps,
    _collect_review_attestations,
    _format_size,
    _format_token_count,
    _merge_config_list,
    _parse_csv_arg,
    _scan_for_text_occurrences,
    _scan_high_entropy_strings,
    _scan_pii,
    _validate_publish_attestation,
    cmd_auth,
    cmd_upload,
    configure,
    export_to_jsonl,
    list_projects,
    main,
)


# --- _format_size ---


class TestFormatSize:
    def test_bytes(self):
        assert _format_size(500) == "500 B"

    def test_kilobytes(self):
        result = _format_size(2048)
        assert "KB" in result

    def test_megabytes(self):
        result = _format_size(5 * 1024 * 1024)
        assert "MB" in result

    def test_gigabytes(self):
        result = _format_size(2 * 1024 * 1024 * 1024)
        assert "GB" in result

    def test_zero(self):
        assert _format_size(0) == "0 B"

    def test_exactly_1024(self):
        result = _format_size(1024)
        assert "KB" in result


# --- _format_token_count ---


class TestFormatTokenCount:
    def test_plain(self):
        assert _format_token_count(500) == "500"

    def test_thousands(self):
        result = _format_token_count(5000)
        assert result == "5K"

    def test_millions(self):
        result = _format_token_count(2_500_000)
        assert "M" in result

    def test_billions(self):
        result = _format_token_count(1_500_000_000)
        assert "B" in result

    def test_zero(self):
        assert _format_token_count(0) == "0"


# --- attestation helpers ---


class TestAttestationHelpers:
    def test_collect_review_attestations_valid(self):
        attestations, errors, manual_count = _collect_review_attestations(
            attest_asked_full_name=(
                "I asked Jane Doe for their full name and scanned the export for Jane Doe."
            ),
            attest_asked_sensitive=(
                "I asked about company, client, and internal names plus URLs; "
                "none were sensitive and no extra redactions were needed."
            ),
            attest_manual_scan=(
                "I performed a manual scan and reviewed 20 sessions across beginning, middle, and end."
            ),
            full_name="Jane Doe",
        )
        assert not errors
        assert manual_count == 20
        assert "Jane Doe" in attestations["asked_full_name"]

    def test_collect_review_attestations_invalid(self):
        _attestations, errors, manual_count = _collect_review_attestations(
            attest_asked_full_name="scanned quickly",
            attest_asked_sensitive="checked stuff",
            attest_manual_scan="manual scan of 5 sessions",
            full_name="Jane Doe",
        )
        assert errors
        assert "asked_full_name" in errors
        assert "asked_sensitive_entities" in errors
        assert "manual_scan_done" in errors
        assert manual_count == 5

    def test_collect_review_attestations_skip_full_name_valid(self):
        _attestations, errors, manual_count = _collect_review_attestations(
            attest_asked_full_name=(
                "User declined to share full name; skipped exact-name scan."
            ),
            attest_asked_sensitive=(
                "I asked about company/client/internal names and private URLs; "
                "none were sensitive and no extra redactions were needed."
            ),
            attest_manual_scan=(
                "I performed a manual scan and reviewed 20 sessions across beginning, middle, and end."
            ),
            full_name=None,
            skip_full_name_scan=True,
        )
        assert not errors
        assert manual_count == 20

    def test_collect_review_attestations_skip_full_name_invalid(self):
        _attestations, errors, _manual_count = _collect_review_attestations(
            attest_asked_full_name="Asked user and scanned it.",
            attest_asked_sensitive=(
                "I asked about company/client/internal names and private URLs; none found."
            ),
            attest_manual_scan=(
                "I performed a manual scan and reviewed 20 sessions across beginning, middle, and end."
            ),
            full_name=None,
            skip_full_name_scan=True,
        )
        assert "asked_full_name" in errors

    def test_validate_publish_attestation(self):
        _normalized, err = _validate_publish_attestation(
            "User explicitly approved publishing this dataset now."
        )
        assert err is None

        _normalized, err = _validate_publish_attestation("ok to go")
        assert err is not None

    def test_validate_publish_attestation_upload(self):
        _normalized, err = _validate_publish_attestation(
            "User explicitly approved uploading this dataset now."
        )
        assert err is None

    def test_scan_for_text_occurrences(self, tmp_path):
        f = tmp_path / "sample.jsonl"
        f.write_text('{"message":"Jane Doe says hi"}\n{"message":"nothing here"}\n')
        result = _scan_for_text_occurrences(f, "Jane Doe")
        assert result["match_count"] == 1


# --- _parse_csv_arg ---


class TestParseCsvArg:
    def test_none(self):
        assert _parse_csv_arg(None) is None

    def test_empty(self):
        assert _parse_csv_arg("") is None

    def test_single(self):
        assert _parse_csv_arg("foo") == ["foo"]

    def test_comma_separated(self):
        assert _parse_csv_arg("foo, bar, baz") == ["foo", "bar", "baz"]

    def test_strips_whitespace(self):
        assert _parse_csv_arg("  a ,  b  ") == ["a", "b"]

    def test_empty_items_filtered(self):
        assert _parse_csv_arg("a,,b,") == ["a", "b"]


# --- _merge_config_list ---


class TestMergeConfigList:
    def test_merge_new_values(self):
        config = {"items": ["a", "b"]}
        _merge_config_list(config, "items", ["c", "d"])
        assert sorted(config["items"]) == ["a", "b", "c", "d"]

    def test_deduplicate(self):
        config = {"items": ["a", "b"]}
        _merge_config_list(config, "items", ["b", "c"])
        assert sorted(config["items"]) == ["a", "b", "c"]

    def test_sorted(self):
        config = {"items": ["z"]}
        _merge_config_list(config, "items", ["a", "m"])
        assert config["items"] == ["a", "m", "z"]

    def test_missing_key(self):
        config = {}
        _merge_config_list(config, "items", ["a"])
        assert config["items"] == ["a"]


# --- export_to_jsonl ---


class TestExportToJsonl:
    def test_writes_jsonl(self, tmp_path, mock_anonymizer, monkeypatch):
        output = tmp_path / "out.jsonl"
        session_data = [{
            "session_id": "s1",
            "model": "claude-sonnet-4-20250514",
            "git_branch": "main",
            "start_time": "2025-01-01T00:00:00",
            "end_time": "2025-01-01T01:00:00",
            "messages": [{"role": "user", "content": "hi"}],
            "stats": {"input_tokens": 100, "output_tokens": 50},
            "project": "test",
        }]
        monkeypatch.setattr(
            "safety_dataclaw.cli.parse_project_sessions",
            lambda *a, **kw: session_data,
        )

        projects = [{"dir_name": "test", "display_name": "test"}]
        meta = export_to_jsonl(projects, output, mock_anonymizer)

        assert output.exists()
        lines = output.read_text().strip().split("\n")
        assert len(lines) == 1
        assert meta["sessions"] == 1

    def test_skips_synthetic_model(self, tmp_path, mock_anonymizer, monkeypatch):
        output = tmp_path / "out.jsonl"
        session_data = [{
            "session_id": "s1",
            "model": "<synthetic>",
            "messages": [{"role": "user", "content": "hi"}],
            "stats": {},
        }]
        monkeypatch.setattr(
            "safety_dataclaw.cli.parse_project_sessions",
            lambda *a, **kw: session_data,
        )
        projects = [{"dir_name": "test", "display_name": "test"}]
        meta = export_to_jsonl(projects, output, mock_anonymizer)
        assert meta["sessions"] == 0
        assert meta["skipped"] == 1

    def test_counts_redactions(self, tmp_path, mock_anonymizer, monkeypatch):
        output = tmp_path / "out.jsonl"
        session_data = [{
            "session_id": "s1",
            "model": "claude-sonnet-4-20250514",
            "messages": [{"role": "user", "content": "Key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz"}],
            "stats": {"input_tokens": 10, "output_tokens": 5},
        }]
        monkeypatch.setattr(
            "safety_dataclaw.cli.parse_project_sessions",
            lambda *a, **kw: session_data,
        )
        projects = [{"dir_name": "test", "display_name": "test"}]
        meta = export_to_jsonl(projects, output, mock_anonymizer)
        assert meta["redactions"] >= 1

    def test_skips_none_model(self, tmp_path, mock_anonymizer, monkeypatch):
        output = tmp_path / "out.jsonl"
        session_data = [{
            "session_id": "s1",
            "model": None,
            "messages": [{"role": "user", "content": "hi"}],
            "stats": {},
        }]
        monkeypatch.setattr(
            "safety_dataclaw.cli.parse_project_sessions",
            lambda *a, **kw: session_data,
        )
        projects = [{"dir_name": "t", "display_name": "t"}]
        meta = export_to_jsonl(projects, output, mock_anonymizer)
        assert meta["sessions"] == 0
        assert meta["skipped"] == 1


# --- configure ---


class TestConfigure:
    def test_merges_exclude(self, tmp_config, monkeypatch, capsys):
        monkeypatch.setattr("safety_dataclaw.cli.CONFIG_FILE", tmp_config)
        monkeypatch.setattr("safety_dataclaw.cli.load_config", lambda: {"excluded_projects": ["a"], "redact_strings": []})
        saved = {}
        monkeypatch.setattr("safety_dataclaw.cli.save_config", lambda c: saved.update(c))

        configure(exclude=["b", "c"])
        assert sorted(saved["excluded_projects"]) == ["a", "b", "c"]

    def test_sets_source(self, tmp_config, monkeypatch, capsys):
        monkeypatch.setattr("safety_dataclaw.cli.CONFIG_FILE", tmp_config)
        monkeypatch.setattr("safety_dataclaw.cli.load_config", lambda: {"source": None})
        saved = {}
        monkeypatch.setattr("safety_dataclaw.cli.save_config", lambda c: saved.update(c))

        configure(source="codex")
        assert saved["source"] == "codex"


# --- list_projects ---


class TestListProjects:
    def test_with_projects(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "safety_dataclaw.cli.discover_projects",
            lambda: [{"display_name": "proj1", "session_count": 5, "total_size_bytes": 1024}],
        )
        monkeypatch.setattr(
            "safety_dataclaw.cli.load_config",
            lambda: {"excluded_projects": []},
        )
        list_projects()
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 1
        assert data[0]["name"] == "proj1"

    def test_no_projects(self, monkeypatch, capsys):
        monkeypatch.setattr("safety_dataclaw.cli.discover_projects", lambda: [])
        list_projects()
        captured = capsys.readouterr()
        assert "No Claude Code, Codex, Gemini CLI, or OpenCode sessions" in captured.out

    def test_source_filter_codex(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "safety_dataclaw.cli.discover_projects",
            lambda: [
                {"display_name": "proj1", "session_count": 5, "total_size_bytes": 1024, "source": "claude"},
                {"display_name": "codex:proj2", "session_count": 3, "total_size_bytes": 512, "source": "codex"},
            ],
        )
        monkeypatch.setattr("safety_dataclaw.cli.load_config", lambda: {"excluded_projects": []})
        list_projects(source_filter="codex")
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 1
        assert data[0]["name"] == "codex:proj2"
        assert data[0]["source"] == "codex"

    def test_no_projects_for_selected_source(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "safety_dataclaw.cli.discover_projects",
            lambda: [{"display_name": "proj1", "session_count": 5, "total_size_bytes": 1024, "source": "claude"}],
        )
        list_projects(source_filter="codex")
        captured = capsys.readouterr()
        assert "No Codex sessions found." in captured.out

    def test_main_list_uses_configured_source_when_auto(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "safety_dataclaw.cli.discover_projects",
            lambda: [
                {"display_name": "proj1", "session_count": 5, "total_size_bytes": 1024, "source": "claude"},
                {"display_name": "codex:proj2", "session_count": 3, "total_size_bytes": 512, "source": "codex"},
            ],
        )
        monkeypatch.setattr("safety_dataclaw.cli.load_config", lambda: {"source": "codex", "excluded_projects": []})
        monkeypatch.setattr("sys.argv", ["safety-dataclaw", "list"])
        main()
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 1
        assert data[0]["name"] == "codex:proj2"


# --- cmd_auth ---


class TestCmdAuth:
    def test_invalid_key_format(self, monkeypatch, capsys):
        monkeypatch.setattr("safety_dataclaw.cli.load_config", lambda: {"traced_url": "https://traced.run"})
        args = MagicMock()
        args.key = "invalid_key_123"
        cmd_auth(args)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "error" in data
        assert "sdcl_" in data["error"]

    def test_successful_auth(self, monkeypatch, capsys):
        saved = {}
        monkeypatch.setattr("safety_dataclaw.cli.load_config", lambda: {"traced_url": "https://traced.run"})
        monkeypatch.setattr("safety_dataclaw.cli.save_config", lambda c: saved.update(c))

        mock_client = MagicMock()
        mock_client.verify.return_value = {"user": {"name": "alice"}}
        monkeypatch.setattr(
            "safety_dataclaw.traced_api.TracedClient",
            lambda api_key, base_url: mock_client,
        )

        args = MagicMock()
        args.key = "sdcl_test_key_12345"
        cmd_auth(args)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "authenticated"
        assert saved.get("api_key") == "sdcl_test_key_12345"
        assert saved.get("stage") == "configure"

    def test_api_error(self, monkeypatch, capsys):
        monkeypatch.setattr("safety_dataclaw.cli.load_config", lambda: {"traced_url": "https://traced.run"})

        from safety_dataclaw.traced_api import TracedApiError

        mock_client = MagicMock()
        mock_client.verify.side_effect = TracedApiError("Invalid or revoked API key")

        monkeypatch.setattr(
            "safety_dataclaw.traced_api.TracedClient",
            lambda api_key, base_url: mock_client,
        )

        args = MagicMock()
        args.key = "sdcl_bad_key_12345"
        cmd_auth(args)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "error" in data
        assert "Invalid" in data["error"]

    def test_auth_via_main(self, monkeypatch, capsys):
        saved = {}
        monkeypatch.setattr("safety_dataclaw.cli.load_config", lambda: {"traced_url": "https://traced.run"})
        monkeypatch.setattr("safety_dataclaw.cli.save_config", lambda c: saved.update(c))

        mock_client = MagicMock()
        mock_client.verify.return_value = {"user": {"name": "alice"}}

        monkeypatch.setattr(
            "safety_dataclaw.traced_api.TracedClient",
            lambda api_key, base_url: mock_client,
        )

        monkeypatch.setattr("sys.argv", ["safety-dataclaw", "auth", "sdcl_test_key_12345"])
        main()
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "authenticated"


# --- cmd_upload ---


class TestCmdUpload:
    def test_not_authenticated(self, monkeypatch, capsys):
        monkeypatch.setattr("safety_dataclaw.cli.load_config", lambda: {})
        args = MagicMock()
        args.file = None
        cmd_upload(args)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "error" in data
        assert "Not authenticated" in data["error"]

    def test_no_export_file(self, monkeypatch, capsys, tmp_path):
        monkeypatch.setattr("safety_dataclaw.cli.load_config", lambda: {"api_key": "sdcl_test"})
        args = MagicMock()
        args.file = str(tmp_path / "nonexistent.jsonl")
        cmd_upload(args)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "error" in data
        assert "No export file found" in data["error"]

    def test_successful_upload(self, monkeypatch, capsys, tmp_path):
        export_file = tmp_path / "export.jsonl"
        export_file.write_text('{"session_id":"s1","model":"claude","messages":[]}\n')

        monkeypatch.setattr("safety_dataclaw.cli.load_config", lambda: {
            "api_key": "sdcl_test",
            "traced_url": "https://traced.run",
            "source": "all",
            "last_export": {"redactions": 3},
        })

        mock_client = MagicMock()
        mock_client.upload.return_value = {"trajectory_ids": ["t1", "t2"]}

        monkeypatch.setattr(
            "safety_dataclaw.traced_api.TracedClient",
            lambda api_key, base_url: mock_client,
        )

        args = MagicMock()
        args.file = str(export_file)
        cmd_upload(args)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "uploaded"
        assert data["count"] == 2
        assert data["trajectory_ids"] == ["t1", "t2"]

    def test_upload_api_error(self, monkeypatch, capsys, tmp_path):
        export_file = tmp_path / "export.jsonl"
        export_file.write_text('{"session_id":"s1","model":"claude","messages":[]}\n')

        monkeypatch.setattr("safety_dataclaw.cli.load_config", lambda: {
            "api_key": "sdcl_test",
            "traced_url": "https://traced.run",
            "source": "all",
        })

        from safety_dataclaw.traced_api import TracedApiError

        mock_client = MagicMock()
        mock_client.upload.side_effect = TracedApiError("API key lacks upload permission")

        monkeypatch.setattr(
            "safety_dataclaw.traced_api.TracedClient",
            lambda api_key, base_url: mock_client,
        )

        args = MagicMock()
        args.file = str(export_file)
        cmd_upload(args)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "error" in data
        assert "upload permission" in data["error"]


class TestWorkflowGateMessages:
    @staticmethod
    def _extract_json(stdout: str) -> dict:
        start = stdout.find("{")
        assert start >= 0, f"No JSON payload found in output: {stdout!r}"
        return json.loads(stdout[start:])

    def test_confirm_without_export_shows_step_process(self, tmp_path, monkeypatch, capsys):
        missing = tmp_path / "missing.jsonl"
        monkeypatch.setattr(
            "sys.argv",
            ["safety-dataclaw", "confirm", "--file", str(missing)],
        )
        with pytest.raises(SystemExit):
            main()
        payload = self._extract_json(capsys.readouterr().out)
        assert payload["error"] == "No export file found."
        assert payload["blocked_on_step"] == "Step 1/3"
        assert len(payload["process_steps"]) == 3
        assert "export --no-push" in payload["process_steps"][0]

    def test_confirm_missing_full_name_explains_purpose_and_skip(self, tmp_path, monkeypatch, capsys):
        export_file = tmp_path / "export.jsonl"
        export_file.write_text('{"project":"p","model":"m","messages":[]}\n')
        monkeypatch.setattr(
            "sys.argv",
            [
                "safety-dataclaw",
                "confirm",
                "--file",
                str(export_file),
                "--attest-full-name",
                "Asked for full name and scanned export.",
                "--attest-sensitive",
                "Asked about company/client/internal names and private URLs; none found.",
                "--attest-manual-scan",
                "Manually scanned 20 sessions across beginning/middle/end and reviewed findings.",
            ],
        )
        with pytest.raises(SystemExit):
            main()
        payload = self._extract_json(capsys.readouterr().out)
        assert payload["error"] == "Missing required --full-name for verification scan."
        assert "--skip-full-name-scan" in payload["hint"]
        assert payload["blocked_on_step"] == "Step 2/3"
        assert len(payload["process_steps"]) == 3

    def test_confirm_skip_full_name_scan_succeeds(self, tmp_path, monkeypatch, capsys):
        export_file = tmp_path / "export.jsonl"
        export_file.write_text('{"project":"p","model":"m","messages":[]}\n')
        monkeypatch.setattr("safety_dataclaw.cli.load_config", lambda: {})
        monkeypatch.setattr("safety_dataclaw.cli.save_config", lambda _c: None)
        monkeypatch.setattr(
            "sys.argv",
            [
                "safety-dataclaw",
                "confirm",
                "--file",
                str(export_file),
                "--skip-full-name-scan",
                "--attest-full-name",
                "User declined to share full name; skipped exact-name scan.",
                "--attest-sensitive",
                "I asked about company/client/internal names and private URLs; none found.",
                "--attest-manual-scan",
                "I performed a manual scan and reviewed 20 sessions across beginning, middle, and end.",
            ],
        )
        main()
        payload = self._extract_json(capsys.readouterr().out)
        assert payload["stage"] == "confirmed"
        assert payload["full_name_scan"]["skipped"] is True

    def test_export_before_confirm_shows_step_process(self, monkeypatch, capsys):
        monkeypatch.setattr("safety_dataclaw.cli.load_config", lambda: {"stage": "review", "source": "all"})
        monkeypatch.setattr("sys.argv", ["safety-dataclaw", "export"])
        with pytest.raises(SystemExit):
            main()
        payload = self._extract_json(capsys.readouterr().out)
        assert payload["error"] == "You must run `safety-dataclaw confirm` before uploading."
        assert payload["blocked_on_step"] == "Step 2/3"
        assert len(payload["process_steps"]) == 3
        assert "confirm" in payload["process_steps"][1]

    def test_export_requires_project_confirmation_with_full_flow(self, monkeypatch, capsys):
        monkeypatch.setattr("safety_dataclaw.cli._has_session_sources", lambda _src: True)
        monkeypatch.setattr(
            "safety_dataclaw.cli.discover_projects",
            lambda: [
                {
                    "display_name": "proj1",
                    "session_count": 2,
                    "total_size_bytes": 1024,
                    "source": "claude",
                }
            ],
        )
        monkeypatch.setattr("safety_dataclaw.cli.load_config", lambda: {"source": "all"})
        monkeypatch.setattr("sys.argv", ["safety-dataclaw", "export", "--no-push"])
        with pytest.raises(SystemExit):
            main()
        payload = self._extract_json(capsys.readouterr().out)
        assert payload["error"] == "Project selection is not confirmed yet."
        assert payload["blocked_on_step"] == "Step 3/6"
        assert len(payload["process_steps"]) == 6
        assert "prep && safety-dataclaw list" in payload["process_steps"][0]
        assert payload["required_action"].startswith("Send the full project/folder list")
        assert "in a message" in payload["required_action"]
        assert isinstance(payload["projects"], list)
        assert payload["projects"][0]["name"] == "proj1"
        assert payload["projects"][0]["sessions"] == 2

    def test_export_requires_explicit_source_selection(self, monkeypatch, capsys):
        monkeypatch.setattr("safety_dataclaw.cli.load_config", lambda: {})
        monkeypatch.setattr("sys.argv", ["safety-dataclaw", "export", "--no-push"])
        with pytest.raises(SystemExit):
            main()
        payload = self._extract_json(capsys.readouterr().out)
        assert payload["error"] == "Source scope is not confirmed yet."
        assert payload["blocked_on_step"] == "Step 2/6"
        assert len(payload["process_steps"]) == 6
        assert payload["allowed_sources"] == ["all", "both", "claude", "codex", "gemini", "opencode"]
        assert payload["next_command"] == "safety-dataclaw config --source all"

    def test_configure_next_steps_require_full_folder_presentation(self):
        steps, _next = _build_status_next_steps(
            "configure",
            {"projects_confirmed": False},
            None,
            None,
        )
        assert any("safety-dataclaw list" in step for step in steps)
        assert any("FULL project/folder list" in step for step in steps)
        assert any("in your next message" in step for step in steps)
        assert any("source scope" in step.lower() for step in steps)

    def test_review_next_steps_explain_full_name_purpose_and_skip_option(self):
        steps, _next = _build_status_next_steps(
            "review",
            {},
            None,
            None,
        )
        assert any("exact-name privacy check" in step for step in steps)
        assert any("--skip-full-name-scan" in step for step in steps)


# --- _scan_high_entropy_strings ---


class TestScanHighEntropyStrings:
    def test_detects_real_secret(self):
        # A realistic API key-like string with high entropy and mixed chars
        secret = "aB3dE6gH9jK2mN5pQ8rS1tU4wX7yZ0c"
        content = f"some config here token {secret} and more text"
        results = _scan_high_entropy_strings(content)
        assert len(results) >= 1
        assert any(r["match"] == secret for r in results)
        # Entropy should be >= 4.0
        for r in results:
            if r["match"] == secret:
                assert r["entropy"] >= 4.0

    def test_filters_uuid(self):
        content = "id=550e8400e29b41d4a716446655440000 done"
        results = _scan_high_entropy_strings(content)
        assert not any("550e8400" in r["match"] for r in results)

    def test_filters_uuid_with_hyphens(self):
        # UUID with hyphens won't match the 20+ contiguous regex, but without hyphens should be filtered
        content = "id=550e8400-e29b-41d4-a716-446655440000 done"
        results = _scan_high_entropy_strings(content)
        assert not any("550e8400" in r["match"] for r in results)

    def test_filters_hex_hash(self):
        content = f"commit=abcdef1234567890abcdef1234567890abcdef12 done"
        results = _scan_high_entropy_strings(content)
        assert not any("abcdef1234567890" in r["match"] for r in results)

    def test_filters_known_prefix_eyj(self):
        content = "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 done"
        results = _scan_high_entropy_strings(content)
        assert not any(r["match"].startswith("eyJ") for r in results)

    def test_filters_known_prefix_ghp(self):
        content = "token=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345 done"
        results = _scan_high_entropy_strings(content)
        assert not any(r["match"].startswith("ghp_") for r in results)

    def test_filters_file_extension_path(self):
        content = "import=some_long_module_name_thing.py done"
        results = _scan_high_entropy_strings(content)
        assert not any(".py" in r["match"] for r in results)

    def test_filters_path_like(self):
        content = "path=src/components/authentication/LoginForm done"
        results = _scan_high_entropy_strings(content)
        assert not any("src/components" in r["match"] for r in results)

    def test_filters_low_entropy(self):
        # Repetitive string with mixed chars but low entropy
        content = "val=aaaaaaBBBBBB111111aaaaaaBBBBBB111111 done"
        results = _scan_high_entropy_strings(content)
        assert not any("aaaaaa" in r["match"] for r in results)

    def test_filters_no_mixed_chars(self):
        # All lowercase - no mixed char types
        content = "val=abcdefghijklmnopqrstuvwxyz done"
        results = _scan_high_entropy_strings(content)
        assert not any("abcdefghijklmnop" in r["match"] for r in results)

    def test_context_snippet(self):
        secret = "aB3dE6gH9jK2mN5pQ8rS1tU4wX7yZ0c"
        prefix = "before_context "
        suffix = " after_context"
        content = prefix + secret + suffix
        results = _scan_high_entropy_strings(content)
        matched = [r for r in results if r["match"] == secret]
        assert len(matched) == 1
        assert "before_context" in matched[0]["context"]
        assert "after_context" in matched[0]["context"]

    def test_results_capped_at_max(self):
        # Generate many distinct high-entropy strings
        import string
        import random
        rng = random.Random(42)
        chars = string.ascii_letters + string.digits
        secrets = []
        for _ in range(25):
            s = "".join(rng.choices(chars, k=30))
            secrets.append(s)
        content = " ".join(f"key={s}" for s in secrets)
        results = _scan_high_entropy_strings(content, max_results=15)
        assert len(results) <= 15

    def test_empty_content(self):
        assert _scan_high_entropy_strings("") == []

    def test_sorted_by_entropy_descending(self):
        secret1 = "aB3dE6gH9jK2mN5pQ8rS1tU4wX7yZ0c"
        secret2 = "Zx9Yw8Xv7Wu6Ts5Rq4Po3Nm2Lk1Jh0G"
        content = f"a={secret1} b={secret2}"
        results = _scan_high_entropy_strings(content)
        if len(results) >= 2:
            assert results[0]["entropy"] >= results[1]["entropy"]

    def test_filters_benign_prefix_https(self):
        content = "url=https://example.com/some/long/path/here done"
        results = _scan_high_entropy_strings(content)
        assert not any(r["match"].startswith("https://") for r in results)

    def test_filters_three_dots(self):
        content = "ver=com.example.app.module.v1.2.3 done"
        results = _scan_high_entropy_strings(content)
        assert not any("com.example.app" in r["match"] for r in results)

    def test_filters_node_modules(self):
        content = "path=some_long_node_modules_path_thing done"
        results = _scan_high_entropy_strings(content)
        assert not any("node_modules" in r["match"] for r in results)


# --- _scan_pii integration with high_entropy_strings ---


class TestScanPiiHighEntropy:
    def test_includes_high_entropy_when_present(self, tmp_path):
        secret = "aB3dE6gH9jK2mN5pQ8rS1tU4wX7yZ0c"
        f = tmp_path / "export.jsonl"
        f.write_text(f'{{"message": "config token {secret} end"}}\n')
        results = _scan_pii(f)
        assert "high_entropy_strings" in results
        assert any(r["match"] == secret for r in results["high_entropy_strings"])

    def test_excludes_high_entropy_when_clean(self, tmp_path):
        f = tmp_path / "export.jsonl"
        f.write_text('{"message": "nothing suspicious here at all"}\n')
        results = _scan_pii(f)
        assert "high_entropy_strings" not in results
