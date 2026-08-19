from __future__ import annotations

from typing import Any
from urllib.parse import quote

import requests

from grafana_alerts.exceptions import ProxyApiError
from grafana_alerts.grafana import ApplyResult, DeleteResult


class ProxyWriteClient:
    """Send alert mutations to the change-control proxy using the Grafana token."""

    def __init__(
        self,
        base_url: str,
        token: str,
        site_key: str,
        org_id: int,
        folder_uid: str,
        artifact_manifest_sha256: str,
        *,
        pipeline: dict[str, str] | None = None,
        timeout: float = 30.0,
        session: requests.Session | None = None,
    ) -> None:
        if not base_url.strip():
            raise ValueError("base_url cannot be empty")
        if not token.strip():
            raise ValueError("token cannot be empty")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.site_key = site_key
        self.org_id = org_id
        self.folder_uid = folder_uid
        self.artifact_manifest_sha256 = artifact_manifest_sha256
        self.pipeline = pipeline or {}
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
        )

    def _request(self, method: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            response = self.session.request(
                method,
                f"{self.base_url}{path}",
                json=payload,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise ProxyApiError(f"Deployment proxy request failed: {exc}") from exc
        try:
            body = response.json()
        except ValueError:
            body = response.text.strip()
        if response.status_code >= 400:
            detail = body.get("detail") if isinstance(body, dict) else body
            if isinstance(detail, dict):
                message = detail.get("message") or detail
                raise ProxyApiError(
                    f"Deployment proxy returned HTTP {response.status_code}: {message}",
                    audit_id=detail.get("auditId"),
                    audit_sha256=detail.get("auditSha256"),
                )
            raise ProxyApiError(
                f"Deployment proxy returned HTTP {response.status_code}: {detail}"
            )
        if not isinstance(body, dict):
            raise ProxyApiError("Deployment proxy returned an unexpected response")
        return body

    def _context(self) -> dict[str, Any]:
        return {
            "orgId": self.org_id,
            "folderUid": self.folder_uid,
            "artifactManifestSha256": self.artifact_manifest_sha256,
            "pipeline": self.pipeline,
        }

    @staticmethod
    def _result(body: dict[str, Any], expected_group: str) -> tuple[int, str, str]:
        group = body.get("group")
        status = body.get("statusCode")
        audit_id = body.get("auditId")
        audit_sha256 = body.get("auditSha256")
        if (
            group != expected_group
            or not isinstance(status, int)
            or not isinstance(audit_id, str)
            or not audit_id
            or not isinstance(audit_sha256, str)
            or len(audit_sha256) != 64
        ):
            raise ProxyApiError("Deployment proxy returned an invalid mutation result")
        return status, audit_id, audit_sha256

    def apply_group(
        self, folder_uid: str, group: str, payload: dict[str, Any]
    ) -> ApplyResult:
        if folder_uid != self.folder_uid:
            raise ProxyApiError("Proxy target folder does not match the reviewed site")
        request = self._context()
        request["payload"] = payload
        path = (
            f"/v1/sites/{quote(self.site_key, safe='')}/groups/"
            f"{quote(group, safe='')}"
        )
        status, audit_id, audit_sha256 = self._result(
            self._request("PUT", path, request), group
        )
        return ApplyResult(group, status, audit_id, audit_sha256)

    def delete_group(self, folder_uid: str, group: str) -> DeleteResult:
        if folder_uid != self.folder_uid:
            raise ProxyApiError("Proxy target folder does not match the reviewed site")
        path = (
            f"/v1/sites/{quote(self.site_key, safe='')}/groups/"
            f"{quote(group, safe='')}:delete"
        )
        status, audit_id, audit_sha256 = self._result(
            self._request("POST", path, self._context()), group
        )
        return DeleteResult(group, status, audit_id, audit_sha256)
