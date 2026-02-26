"""TRACED API client for safety-dataclaw."""

from typing import Any

import requests

from . import __version__


class TracedApiError(Exception):
    """Raised when the TRACED API returns an error."""

    pass


class TracedClient:
    """HTTP client for the traced.run API.

    Wraps three endpoints:
    - verify: check that an API key is valid
    - upload: send sanitized sessions to traced.run
    - list_datasets: retrieve the user's trajectory datasets
    """

    def __init__(self, api_key: str, base_url: str = "https://traced.run"):
        is_localhost = base_url.startswith("http://localhost") or base_url.startswith("http://127.0.0.1")
        if not base_url.startswith("https://") and not is_localhost:
            raise TracedApiError(
                f"Refusing to connect to non-HTTPS URL: {base_url}. "
                "API keys must only be sent over HTTPS."
            )
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": f"safety-dataclaw/{__version__}",
        }

    def verify(self) -> dict[str, Any]:
        """Verify the API key against traced.run.

        Returns the user info and scopes on success.
        Raises TracedApiError if the key is invalid or revoked.
        """
        resp = requests.get(
            f"{self.base_url}/api/auth/verify",
            headers=self._headers(),
            timeout=15,
        )
        if resp.status_code == 401:
            raise TracedApiError("Invalid or revoked API key")
        resp.raise_for_status()
        return resp.json()

    def upload(
        self,
        sessions: list[dict],
        source: str,
        metadata: dict | None = None,
    ) -> dict[str, Any]:
        """Upload sanitized sessions to traced.run.

        Args:
            sessions: List of session dicts to upload.
            source: The agent source identifier (e.g. "claude", "cursor").
            metadata: Optional metadata dict to include with the upload.

        Returns:
            Response dict with trajectory_ids and status.

        Raises:
            TracedApiError: If the key is invalid or lacks upload permission.
        """
        body = {
            "sessions": sessions,
            "source": source,
            "metadata": metadata or {},
        }
        resp = requests.post(
            f"{self.base_url}/api/cli/upload",
            headers=self._headers(),
            json=body,
            timeout=120,
        )
        if resp.status_code == 401:
            raise TracedApiError("Invalid or revoked API key")
        if resp.status_code == 403:
            raise TracedApiError("API key lacks upload permission")
        resp.raise_for_status()
        return resp.json()

    def list_datasets(self) -> list[dict]:
        """List the user's trajectory datasets.

        Returns:
            A list of dataset dicts.
        """
        resp = requests.get(
            f"{self.base_url}/api/trajectories/datasets",
            headers=self._headers(),
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json().get("datasets", [])
