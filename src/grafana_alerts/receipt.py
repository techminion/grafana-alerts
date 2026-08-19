from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from grafana_alerts.exceptions import ConfigError

RECEIPT_SCHEMA_VERSION = 1
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_PIPELINE_ENVIRONMENT = {
    "buildId": "BUILD_BUILDID",
    "buildNumber": "BUILD_BUILDNUMBER",
    "sourceVersion": "BUILD_SOURCEVERSION",
    "repository": "BUILD_REPOSITORY_NAME",
    "teamProject": "SYSTEM_TEAMPROJECT",
    "stage": "SYSTEM_STAGEDISPLAYNAME",
    "job": "SYSTEM_JOBDISPLAYNAME",
}


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: str | Path) -> str:
    source = Path(path)
    try:
        return hashlib.sha256(source.read_bytes()).hexdigest()
    except OSError as exc:
        raise ConfigError(f"Unable to fingerprint {source}: {exc}") from exc


def pipeline_metadata(environment: dict[str, str] | None = None) -> dict[str, str]:
    values = os.environ if environment is None else environment
    return {
        key: values[variable]
        for key, variable in _PIPELINE_ENVIRONMENT.items()
        if values.get(variable)
    }


def receipt_sidecar(path: str | Path) -> Path:
    receipt_path = Path(path)
    return receipt_path.with_name(f"{receipt_path.name}.sha256")


def ensure_receipt_target_available(path: str | Path) -> None:
    receipt_path = Path(path)
    sidecar_path = receipt_sidecar(receipt_path)
    existing = [candidate for candidate in (receipt_path, sidecar_path) if candidate.exists()]
    if existing:
        names = ", ".join(str(candidate) for candidate in existing)
        raise ConfigError(f"Deployment receipt target already exists: {names}")
    try:
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ConfigError(f"Unable to prepare deployment receipt directory: {exc}") from exc


@dataclass
class ReceiptRecorder:
    started_at: str = field(default_factory=utc_timestamp)
    site: str | None = None
    org_id: int | None = None
    folder_uid: str | None = None
    identity: str | None = None
    artifact_manifest_sha256: str | None = None
    deployment_plan_sha256: str | None = None
    pipeline: dict[str, str] = field(default_factory=pipeline_metadata)
    operations: list[dict[str, Any]] = field(default_factory=list)
    rollback: dict[str, str] | None = None

    def target(self, site: str, org_id: int, folder_uid: str) -> None:
        self.site = site
        self.org_id = org_id
        self.folder_uid = folder_uid

    def record(
        self,
        group: str,
        action: str,
        status: str,
        *,
        http_status: int | None = None,
        error: str | None = None,
    ) -> None:
        operation: dict[str, Any] = {
            "group": group,
            "action": action,
            "status": status,
        }
        if http_status is not None:
            operation["httpStatus"] = http_status
        if error is not None:
            operation["error"] = error
        self.operations.append(operation)

    def link_rollback(
        self,
        reason: str,
        source_receipt_sha256: str,
        rollback_plan_sha256: str,
    ) -> None:
        self.rollback = {
            "reason": reason,
            "sourceReceiptSha256": source_receipt_sha256,
            "planSha256": rollback_plan_sha256,
        }

    def payload(
        self,
        status: str,
        error: str | None = None,
        *,
        finished_at: str | None = None,
    ) -> dict[str, Any]:
        payload = {
            "schemaVersion": RECEIPT_SCHEMA_VERSION,
            "status": status,
            "startedAt": self.started_at,
            "finishedAt": finished_at or utc_timestamp(),
            "site": self.site,
            "orgId": self.org_id,
            "folderUid": self.folder_uid,
            "identity": self.identity,
            "artifactManifestSha256": self.artifact_manifest_sha256,
            "deploymentPlanSha256": self.deployment_plan_sha256,
            "operations": self.operations,
            "error": error,
            "pipeline": self.pipeline,
        }
        if self.rollback is not None:
            payload["rollback"] = self.rollback
        return payload


def validate_receipt(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ConfigError("Deployment receipt must contain a JSON object")
    required = {
        "schemaVersion",
        "status",
        "startedAt",
        "finishedAt",
        "site",
        "orgId",
        "folderUid",
        "identity",
        "artifactManifestSha256",
        "deploymentPlanSha256",
        "operations",
        "error",
        "pipeline",
    }
    missing = required - payload.keys()
    if missing:
        raise ConfigError(f"Deployment receipt is missing: {', '.join(sorted(missing))}")
    if payload["schemaVersion"] != RECEIPT_SCHEMA_VERSION:
        raise ConfigError(
            f"Unsupported deployment receipt schema: {payload['schemaVersion']}"
        )
    if payload["status"] not in {"succeeded", "failed"}:
        raise ConfigError("Deployment receipt has an invalid status")
    for timestamp in ("startedAt", "finishedAt"):
        if not isinstance(payload[timestamp], str) or not payload[timestamp]:
            raise ConfigError(f"Deployment receipt has an invalid {timestamp}")
    for key in ("site", "folderUid", "identity", "error"):
        if payload[key] is not None and not isinstance(payload[key], str):
            raise ConfigError(f"Deployment receipt has an invalid {key}")
    if payload["orgId"] is not None and not isinstance(payload["orgId"], int):
        raise ConfigError("Deployment receipt has an invalid orgId")
    for key in ("artifactManifestSha256", "deploymentPlanSha256"):
        value = payload[key]
        if value is not None and (
            not isinstance(value, str) or not _SHA256_PATTERN.fullmatch(value)
        ):
            raise ConfigError(f"Deployment receipt has an invalid {key}")
    if not isinstance(payload["pipeline"], dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in payload["pipeline"].items()
    ):
        raise ConfigError("Deployment receipt has invalid pipeline metadata")
    if not isinstance(payload["operations"], list):
        raise ConfigError("Deployment receipt operations must be a list")
    for operation in payload["operations"]:
        if (
            not isinstance(operation, dict)
            or not isinstance(operation.get("group"), str)
            or operation.get("action") not in {"apply", "delete"}
            or operation.get("status") not in {"succeeded", "failed"}
        ):
            raise ConfigError("Deployment receipt contains an invalid operation")
        if "httpStatus" in operation and not isinstance(operation["httpStatus"], int):
            raise ConfigError("Deployment receipt operation has an invalid HTTP status")
        if "error" in operation and not isinstance(operation["error"], str):
            raise ConfigError("Deployment receipt operation has an invalid error")
    if payload["status"] == "failed" and not payload["error"]:
        raise ConfigError("Failed deployment receipt must include an error")
    rollback = payload.get("rollback")
    if rollback is not None:
        if not isinstance(rollback, dict) or set(rollback) != {
            "reason",
            "sourceReceiptSha256",
            "planSha256",
        }:
            raise ConfigError("Deployment receipt has invalid rollback metadata")
        if not isinstance(rollback["reason"], str) or not rollback["reason"].strip():
            raise ConfigError("Deployment receipt has invalid rollback reason")
        for key in ("sourceReceiptSha256", "planSha256"):
            if (
                not isinstance(rollback[key], str)
                or not _SHA256_PATTERN.fullmatch(rollback[key])
            ):
                raise ConfigError(f"Deployment receipt has invalid rollback {key}")
    return payload


def write_receipt(path: str | Path, payload: dict[str, Any]) -> str:
    validate_receipt(payload)
    receipt_path = Path(path)
    ensure_receipt_target_available(receipt_path)
    content = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    digest = hashlib.sha256(content).hexdigest()
    try:
        with receipt_path.open("xb") as receipt_file:
            receipt_file.write(content)
        with receipt_sidecar(receipt_path).open("x", encoding="utf-8") as sidecar_file:
            sidecar_file.write(f"{digest}  {receipt_path.name}\n")
    except OSError as exc:
        raise ConfigError(f"Unable to write deployment receipt {receipt_path}: {exc}") from exc
    return digest


def load_and_verify_receipt(path: str | Path) -> dict[str, Any]:
    receipt_path = Path(path)
    sidecar_path = receipt_sidecar(receipt_path)
    try:
        content = receipt_path.read_bytes()
        sidecar = sidecar_path.read_text(encoding="utf-8").split()
        payload = json.loads(content)
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Unable to read deployment receipt {receipt_path}: {exc}") from exc
    if not sidecar or not _SHA256_PATTERN.fullmatch(sidecar[0]):
        raise ConfigError(f"Invalid deployment receipt sidecar: {sidecar_path}")
    actual = hashlib.sha256(content).hexdigest()
    if actual != sidecar[0]:
        raise ConfigError(
            f"Deployment receipt integrity check failed: expected {sidecar[0]}, found {actual}"
        )
    return validate_receipt(payload)
