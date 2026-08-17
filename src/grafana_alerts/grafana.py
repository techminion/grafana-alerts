from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import requests

from grafana_alerts.exceptions import GrafanaApiError


@dataclass(frozen=True)
class ApplyResult:
    group: str
    status_code: int


class GrafanaClient:
    """Client for Grafana's legacy provisioning API.

    Grafana 13 deprecates these routes but keeps them operational. Keeping the
    route construction here makes a later App Platform API adapter isolated.
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout: float = 30.0,
        session: requests.Session | None = None,
    ) -> None:
        if not base_url.strip():
            raise ValueError("base_url cannot be empty")
        if not token.strip():
            raise ValueError("token cannot be empty")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
        )

    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        try:
            response = self.session.request(
                method,
                f"{self.base_url}{path}",
                timeout=self.timeout,
                **kwargs,
            )
        except requests.RequestException as exc:
            raise GrafanaApiError(f"Grafana request failed: {exc}") from exc

        if response.status_code >= 400:
            try:
                detail = response.json()
            except ValueError:
                detail = response.text.strip()
            raise GrafanaApiError(
                f"Grafana returned HTTP {response.status_code} for {method} {path}: {detail}"
            )
        return response

    def whoami(self) -> dict[str, Any]:
        response = self._request("GET", "/api/user")
        body = response.json()
        if not isinstance(body, dict):
            raise GrafanaApiError("Grafana /api/user returned an unexpected response")
        return body

    def get_group(self, folder_uid: str, group: str) -> dict[str, Any] | None:
        path = self._group_path(folder_uid, group)
        try:
            response = self._request("GET", path)
        except GrafanaApiError as exc:
            if "HTTP 404" in str(exc):
                return None
            raise
        body = response.json()
        if not isinstance(body, dict):
            raise GrafanaApiError(f"Grafana returned an unexpected rule group for {group}")
        return body

    def apply_group(self, folder_uid: str, group: str, payload: dict[str, Any]) -> ApplyResult:
        response = self._request("PUT", self._group_path(folder_uid, group), json=payload)
        return ApplyResult(group=group, status_code=response.status_code)

    @staticmethod
    def _group_path(folder_uid: str, group: str) -> str:
        return (
            "/api/v1/provisioning/folder/"
            f"{quote(folder_uid, safe='')}/rule-groups/{quote(group, safe='')}"
        )

