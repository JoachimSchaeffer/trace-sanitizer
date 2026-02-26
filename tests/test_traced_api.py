# tests/test_traced_api.py
import pytest
from unittest.mock import patch, MagicMock
from safety_dataclaw.traced_api import TracedClient, TracedApiError


class TestTracedClient:
    def test_init_with_key(self):
        client = TracedClient(api_key="sdcl_test", base_url="https://traced.run")
        assert client.api_key == "sdcl_test"
        assert client.base_url == "https://traced.run"

    def test_base_url_strips_trailing_slash(self):
        client = TracedClient(api_key="sdcl_test", base_url="https://traced.run/")
        assert client.base_url == "https://traced.run"

    def test_auth_header(self):
        client = TracedClient(api_key="sdcl_test", base_url="https://traced.run")
        headers = client._headers()
        assert headers["Authorization"] == "Bearer sdcl_test"
        assert "User-Agent" in headers

    @patch("safety_dataclaw.traced_api.requests.get")
    def test_verify_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"user": {"handle": "test"}, "scopes": ["upload"]}
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        client = TracedClient(api_key="sdcl_test", base_url="https://traced.run")
        result = client.verify()
        assert result["user"]["handle"] == "test"
        mock_get.assert_called_once()

    @patch("safety_dataclaw.traced_api.requests.get")
    def test_verify_invalid_key(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.json.return_value = {"error": "Invalid key"}
        mock_get.return_value = mock_resp

        client = TracedClient(api_key="sdcl_bad", base_url="https://traced.run")
        with pytest.raises(TracedApiError, match="Invalid or revoked API key"):
            client.verify()

    @patch("safety_dataclaw.traced_api.requests.post")
    def test_upload_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"trajectory_ids": ["uuid1"], "status": "private"}
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        client = TracedClient(api_key="sdcl_test", base_url="https://traced.run")
        result = client.upload(sessions=[{"title": "test", "content": "data"}], source="claude")
        assert result["status"] == "private"
        assert len(result["trajectory_ids"]) == 1

    @patch("safety_dataclaw.traced_api.requests.post")
    def test_upload_forbidden(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_post.return_value = mock_resp

        client = TracedClient(api_key="sdcl_test", base_url="https://traced.run")
        with pytest.raises(TracedApiError, match="upload permission"):
            client.upload(sessions=[{"title": "test"}], source="claude")

    @patch("safety_dataclaw.traced_api.requests.get")
    def test_list_datasets(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"datasets": [{"id": "1", "title": "test"}]}
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        client = TracedClient(api_key="sdcl_test", base_url="https://traced.run")
        datasets = client.list_datasets()
        assert len(datasets) == 1
        assert datasets[0]["title"] == "test"
