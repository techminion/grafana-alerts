from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import requests

from grafana_alerts.exceptions import GrafanaApiError


@dataclass(frozen=True)
class ApplyResult:
    group: str
    status_code: int


@dataclass(frozen=True)
class DeleteResult:
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

    def list_datasources(self) -> list[dict[str, Any]]:
        """Return data sources visible to the authenticated Grafana identity."""
        body = self._request("GET", "/api/datasources").json()
        if not isinstance(body, list) or not all(isinstance(item, dict) for item in body):
            raise GrafanaApiError("Grafana /api/datasources returned an unexpected response")
        return body

    def prometheus_metrics(self, datasource_uid: str) -> list[str]:
        """Return metric names through Grafana's authenticated data source proxy."""
        return self.prometheus_label_values(datasource_uid, "__name__")

    def prometheus_labels(
        self,
        datasource_uid: str,
        *,
        metric: str | None = None,
    ) -> list[str]:
        """Return label names, optionally scoped to a Prometheus metric."""
        params = self._metric_params(metric)
        data = self._prometheus_get(datasource_uid, "/api/v1/labels", params=params)
        if not isinstance(data, list) or not all(isinstance(item, str) for item in data):
            raise GrafanaApiError("Prometheus labels endpoint returned an unexpected response")
        return data

    def prometheus_label_values(
        self,
        datasource_uid: str,
        label: str,
        *,
        metric: str | None = None,
    ) -> list[str]:
        """Return values for a label, optionally scoped to a Prometheus metric."""
        if not label.strip():
            raise GrafanaApiError("Prometheus label cannot be empty")
        path = f"/api/v1/label/{quote(label, safe='')}/values"
        data = self._prometheus_get(datasource_uid, path, params=self._metric_params(metric))
        if not isinstance(data, list) or not all(isinstance(item, str) for item in data):
            raise GrafanaApiError(
                "Prometheus label values endpoint returned an unexpected response"
            )
        return data

    def query_prometheus(
        self,
        datasource_uid: str,
        expression: str,
        *,
        time: str | None = None,
    ) -> dict[str, Any]:
        """Run an instant PromQL query through Grafana's authenticated proxy."""
        if not expression.strip():
            raise GrafanaApiError("PromQL expression cannot be empty")
        params = {"query": expression}
        if time is not None:
            params["time"] = time
        data = self._prometheus_get(datasource_uid, "/api/v1/query", params=params)
        if not isinstance(data, dict):
            raise GrafanaApiError("Prometheus query endpoint returned an unexpected response")
        return data

    def _prometheus_get(
        self,
        datasource_uid: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
    ) -> Any:
        proxy_path = (
            f"/api/datasources/proxy/uid/{quote(datasource_uid, safe='')}"
            f"{path}"
        )
        body = self._request("GET", proxy_path, params=params).json()
        if not isinstance(body, dict):
            raise GrafanaApiError("Prometheus returned an unexpected response")
        if body.get("status") != "success":
            detail = body.get("error") or body
            raise GrafanaApiError(f"Prometheus query failed: {detail}")
        if "data" not in body:
            raise GrafanaApiError("Prometheus response did not include data")
        return body["data"]

    @staticmethod
    def _metric_params(metric: str | None) -> dict[str, str] | None:
        if metric is None:
            return None
        if not re.fullmatch(r"[a-zA-Z_:][a-zA-Z0-9_:]*", metric):
            raise GrafanaApiError(f"Invalid Prometheus metric name: {metric}")
        return {"match[]": metric}

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

    def delete_group(self, folder_uid: str, group: str) -> DeleteResult:
        response = self._request("DELETE", self._group_path(folder_uid, group))
        return DeleteResult(group=group, status_code=response.status_code)

    @staticmethod
    def _group_path(folder_uid: str, group: str) -> str:
        return (
            "/api/v1/provisioning/folder/"
            f"{quote(folder_uid, safe='')}/rule-groups/{quote(group, safe='')}"
        )
