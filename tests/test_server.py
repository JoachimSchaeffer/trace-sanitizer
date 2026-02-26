"""Tests for the FastAPI sanitization microservice."""

from fastapi.testclient import TestClient

from server.app import app

client = TestClient(app)


# --- Health endpoint ---


class TestHealth:
    def test_health_returns_200(self):
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_body(self):
        response = client.get("/health")
        assert response.json() == {"status": "ok"}


# --- Sanitize endpoint: basic behavior ---


class TestSanitizeBasic:
    def test_empty_content(self):
        response = client.post("/sanitize", json={"content": ""})
        assert response.status_code == 200
        data = response.json()
        assert data["sanitized"] == ""
        assert data["findings"] == []
        assert data["redaction_count"] == 0

    def test_clean_text_unchanged(self):
        text = "Hello, this is perfectly clean text with no secrets."
        response = client.post("/sanitize", json={"content": text})
        assert response.status_code == 200
        data = response.json()
        assert data["sanitized"] == text
        assert data["findings"] == []
        assert data["redaction_count"] == 0


# --- Sanitize endpoint: secret redaction ---


class TestSanitizeSecretRedaction:
    def test_anthropic_key_redacted(self):
        key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"
        text = f"My API key is {key}"
        response = client.post("/sanitize", json={"content": text})
        assert response.status_code == 200
        data = response.json()
        assert key not in data["sanitized"]
        assert "[REDACTED]" in data["sanitized"]
        assert data["redaction_count"] >= 1

    def test_openai_key_redacted(self):
        key = "sk-" + "a" * 48
        text = f"OpenAI key: {key}"
        response = client.post("/sanitize", json={"content": text})
        data = response.json()
        assert key not in data["sanitized"]
        assert data["redaction_count"] >= 1

    def test_github_token_redacted(self):
        token = "ghp_" + "a" * 36
        text = f"GitHub token: {token}"
        response = client.post("/sanitize", json={"content": text})
        data = response.json()
        assert token not in data["sanitized"]
        assert data["redaction_count"] >= 1

    def test_email_redacted(self):
        text = "Contact user@company.com for help"
        response = client.post("/sanitize", json={"content": text})
        data = response.json()
        assert "user@company.com" not in data["sanitized"]
        assert data["redaction_count"] >= 1

    def test_multiple_secrets_redacted(self):
        key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"
        text = f"Key: {key} and email: user@company.com"
        response = client.post("/sanitize", json={"content": text})
        data = response.json()
        assert key not in data["sanitized"]
        assert "user@company.com" not in data["sanitized"]
        assert data["redaction_count"] >= 2


# --- Sanitize endpoint: findings ---


class TestSanitizeFindings:
    def test_findings_list_populated(self):
        key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"
        text = f"My key is {key}"
        response = client.post("/sanitize", json={"content": text})
        data = response.json()
        assert len(data["findings"]) >= 1

    def test_findings_have_correct_structure(self):
        key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"
        text = f"Key: {key}"
        response = client.post("/sanitize", json={"content": text})
        data = response.json()
        for finding in data["findings"]:
            assert "type" in finding
            assert "start" in finding
            assert "end" in finding
            assert "match" in finding
            assert isinstance(finding["type"], str)
            assert isinstance(finding["start"], int)
            assert isinstance(finding["end"], int)

    def test_findings_type_is_correct(self):
        key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"
        text = f"Key: {key}"
        response = client.post("/sanitize", json={"content": text})
        data = response.json()
        types = [f["type"] for f in data["findings"]]
        assert "anthropic_key" in types

    def test_no_findings_for_clean_text(self):
        response = client.post("/sanitize", json={"content": "just normal text"})
        data = response.json()
        assert data["findings"] == []


# --- Sanitize endpoint: custom redact_strings ---


class TestSanitizeCustomStrings:
    def test_custom_string_redacted(self):
        text = "My company is Acme Corporation and we love Acme Corporation"
        response = client.post(
            "/sanitize",
            json={"content": text, "redact_strings": ["Acme Corporation"]},
        )
        data = response.json()
        assert "Acme Corporation" not in data["sanitized"]
        assert data["redaction_count"] >= 2

    def test_custom_string_with_no_match(self):
        text = "Hello world"
        response = client.post(
            "/sanitize",
            json={"content": text, "redact_strings": ["nonexistent"]},
        )
        data = response.json()
        assert data["sanitized"] == text
        assert data["redaction_count"] == 0

    def test_custom_string_combined_with_secret_detection(self):
        key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"
        text = f"Key: {key} and company: Acme Corp"
        response = client.post(
            "/sanitize",
            json={"content": text, "redact_strings": ["Acme Corp"]},
        )
        data = response.json()
        assert key not in data["sanitized"]
        assert "Acme Corp" not in data["sanitized"]
        assert data["redaction_count"] >= 2

    def test_empty_redact_strings_list(self):
        text = "Hello world"
        response = client.post(
            "/sanitize",
            json={"content": text, "redact_strings": []},
        )
        data = response.json()
        assert data["sanitized"] == text
        assert data["redaction_count"] == 0


# --- Sanitize endpoint: username anonymization ---


class TestSanitizeAnonymization:
    def test_username_anonymized(self):
        text = "The user johndoe logged in from /home/johndoe/project"
        response = client.post(
            "/sanitize",
            json={"content": text, "anonymize_usernames": ["johndoe"]},
        )
        data = response.json()
        assert "johndoe" not in data["sanitized"]

    def test_anonymize_with_no_usernames(self):
        text = "Hello world"
        response = client.post(
            "/sanitize",
            json={"content": text, "anonymize_usernames": []},
        )
        data = response.json()
        # Empty list should not trigger anonymization
        assert data["sanitized"] == text


# --- Sanitize endpoint: redaction_count accuracy ---


class TestSanitizeRedactionCount:
    def test_single_redaction_count(self):
        key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"
        text = f"Key: {key}"
        response = client.post("/sanitize", json={"content": text})
        data = response.json()
        assert data["redaction_count"] == 1

    def test_zero_redaction_count_for_clean_text(self):
        response = client.post("/sanitize", json={"content": "clean text"})
        data = response.json()
        assert data["redaction_count"] == 0

    def test_custom_string_counted(self):
        text = "mycompany is great mycompany rocks"
        response = client.post(
            "/sanitize",
            json={"content": text, "redact_strings": ["mycompany"]},
        )
        data = response.json()
        assert data["redaction_count"] == 2


# --- Sanitize endpoint: validation ---


class TestSanitizeValidation:
    def test_missing_content_field(self):
        response = client.post("/sanitize", json={})
        assert response.status_code == 422

    def test_non_string_content(self):
        response = client.post("/sanitize", json={"content": 123})
        assert response.status_code == 422


# --- Docs disabled ---


class TestDocsDisabled:
    def test_docs_url_disabled(self):
        response = client.get("/docs")
        assert response.status_code == 404

    def test_redoc_url_disabled(self):
        response = client.get("/redoc")
        assert response.status_code == 404
