from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

import requests

from grafana_alerts.attestation import create_mutation_attestation
from grafana_alerts.deployment_plan import live_group_sha256
from grafana_alerts.exceptions import ProxyApiError
from grafana_alerts.grafana import ApplyResult, DeleteResult

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


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
        attestation_key: str,
        *,
        pipeline: dict[str, str] | None = None,
        timeout: float = 30.0,
        session: requests.Session | None = None,
    ) -> None:
        if not base_url.strip():
            raise ValueError("base_url cannot be empty")
        if not token.strip():
            raise ValueError("token cannot be empty")
        if len(attestation_key.encode()) < 32:
            raise ValueError("attestation_key must be at least 32 bytes")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.site_key = site_key
        self.org_id = org_id
        self.folder_uid = folder_uid
        self.artifact_manifest_sha256 = artifact_manifest_sha256
        self.attestation_key = attestation_key
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

    def _attestation(
        self,
        group: str,
        operation: str,
        *,
        payload_sha256: str | None = None,
        expected_before_sha256: str | None = None,
    ) -> dict[str, Any]:
        return create_mutation_attestation(
            self.attestation_key,
            site=self.site_key,
            org_id=self.org_id,
            folder_uid=self.folder_uid,
            group=group,
            operation=operation,
            artifact_manifest_sha256=self.artifact_manifest_sha256,
            payload_sha256=payload_sha256,
            expected_before_sha256=expected_before_sha256,
        )

    def _context(self, attestation: dict[str, Any]) -> dict[str, Any]:
        return {
            "orgId": self.org_id,
            "folderUid": self.folder_uid,
            "artifactManifestSha256": self.artifact_manifest_sha256,
            "pipeline": self.pipeline,
            "attestation": attestation,
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
        request = self._context(
            self._attestation(
                group,
                "apply",
                payload_sha256=live_group_sha256(payload),
            )
        )
        request["payload"] = payload
        path = (
            f"/v1/sites/{quote(self.site_key, safe='')}/groups/"
            f"{quote(group, safe='')}"
        )
        status, audit_id, audit_sha256 = self._result(
            self._request("PUT", path, request), group
        )
        return ApplyResult(group, status, audit_id, audit_sha256)

    def delete_group(
        self, folder_uid: str, group: str, expected_before_sha256: str
    ) -> DeleteResult:
        if folder_uid != self.folder_uid:
            raise ProxyApiError("Proxy target folder does not match the reviewed site")
        if not _SHA256.fullmatch(expected_before_sha256):
            raise ProxyApiError("Delete requires the reviewed live before-state fingerprint")
        path = (
            f"/v1/sites/{quote(self.site_key, safe='')}/groups/"
            f"{quote(group, safe='')}:delete"
        )
        status, audit_id, audit_sha256 = self._result(
            self._request(
                "POST",
                path,
                self._context(
                    self._attestation(
                        group,
                        "delete",
                        expected_before_sha256=expected_before_sha256,
                    )
                ),
            ),
            group,
        )
        return DeleteResult(group, status, audit_id, audit_sha256)
