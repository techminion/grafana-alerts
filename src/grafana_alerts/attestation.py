from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from grafana_alerts.exceptions import ConfigError

ATTESTATION_SCHEMA_VERSION = 1
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_NONCE = re.compile(r"^[0-9a-f]{32}$")
_STATEMENT_KEYS = {
    "schemaVersion",
    "algorithm",
    "issuedAt",
    "expiresAt",
    "nonce",
    "site",
    "orgId",
    "folderUid",
    "group",
    "operation",
    "artifactManifestSha256",
    "payloadSha256",
    "expectedBeforeSha256",
}


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object, name: str) -> datetime:
    if not isinstance(value, str):
        raise ConfigError(f"Mutation attestation has an invalid {name}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ConfigError(f"Mutation attestation has an invalid {name}") from exc
    if parsed.tzinfo is None:
        raise ConfigError(f"Mutation attestation has an invalid {name}")
    return parsed.astimezone(timezone.utc)


def _canonical(statement: dict[str, Any]) -> bytes:
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()


def _signature(key: str, statement: dict[str, Any]) -> str:
    return hmac.new(key.encode(), _canonical(statement), hashlib.sha256).hexdigest()


def mutation_attestation_sha256(envelope: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(envelope)).hexdigest()


def create_mutation_attestation(
    key: str,
    *,
    site: str,
    org_id: int,
    folder_uid: str,
    group: str,
    operation: str,
    artifact_manifest_sha256: str,
    payload_sha256: str | None,
    expected_before_sha256: str | None,
    ttl_seconds: int = 600,
    now: datetime | None = None,
    nonce: str | None = None,
) -> dict[str, Any]:
    if len(key.encode()) < 32:
        raise ConfigError("Mutation attestation key must be at least 32 bytes")
    if operation not in {"apply", "delete"}:
        raise ConfigError(f"Unsupported attested mutation: {operation}")
    if ttl_seconds < 1:
        raise ConfigError("Mutation attestation TTL must be positive")
    issued = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    statement = {
        "schemaVersion": ATTESTATION_SCHEMA_VERSION,
        "algorithm": "HMAC-SHA256",
        "issuedAt": _timestamp(issued),
        "expiresAt": _timestamp(issued + timedelta(seconds=ttl_seconds)),
        "nonce": nonce or secrets.token_hex(16),
        "site": site,
        "orgId": org_id,
        "folderUid": folder_uid,
        "group": group,
        "operation": operation,
        "artifactManifestSha256": artifact_manifest_sha256,
        "payloadSha256": payload_sha256,
        "expectedBeforeSha256": expected_before_sha256,
    }
    _validate_statement_shape(statement)
    return {"statement": statement, "signature": _signature(key, statement)}


def _validate_statement_shape(statement: object) -> dict[str, Any]:
    if not isinstance(statement, dict) or set(statement) != _STATEMENT_KEYS:
        raise ConfigError("Mutation attestation statement has invalid fields")
    if (
        statement["schemaVersion"] != ATTESTATION_SCHEMA_VERSION
        or statement["algorithm"] != "HMAC-SHA256"
        or not isinstance(statement["site"], str)
        or not statement["site"]
        or not isinstance(statement["orgId"], int)
        or not isinstance(statement["folderUid"], str)
        or not statement["folderUid"]
        or not isinstance(statement["group"], str)
        or not statement["group"]
        or statement["operation"] not in {"apply", "delete"}
        or not isinstance(statement["artifactManifestSha256"], str)
        or not _SHA256.fullmatch(statement["artifactManifestSha256"])
        or not isinstance(statement["nonce"], str)
        or not _NONCE.fullmatch(statement["nonce"])
    ):
        raise ConfigError("Mutation attestation statement is invalid")
    for name in ("payloadSha256", "expectedBeforeSha256"):
        value = statement[name]
        if value is not None and (
            not isinstance(value, str) or not _SHA256.fullmatch(value)
        ):
            raise ConfigError(f"Mutation attestation has an invalid {name}")
    if statement["operation"] == "apply" and (
        statement["payloadSha256"] is None
        or statement["expectedBeforeSha256"] is not None
    ):
        raise ConfigError("Apply attestation must bind only the desired payload")
    if statement["operation"] == "delete" and (
        statement["payloadSha256"] is not None
        or statement["expectedBeforeSha256"] is None
    ):
        raise ConfigError("Delete attestation must bind only the live before-state")
    return statement


def verify_mutation_attestation(
    envelope: object,
    key: str,
    *,
    expected: dict[str, Any],
    max_ttl_seconds: int = 900,
    clock_skew_seconds: int = 60,
    now: datetime | None = None,
) -> dict[str, Any]:
    if len(key.encode()) < 32:
        raise ConfigError("Mutation attestation key must be at least 32 bytes")
    if max_ttl_seconds < 1 or clock_skew_seconds < 0:
        raise ConfigError("Mutation attestation verifier timing limits are invalid")
    if not isinstance(envelope, dict) or set(envelope) != {"statement", "signature"}:
        raise ConfigError("Mutation attestation envelope is invalid")
    statement = _validate_statement_shape(envelope["statement"])
    signature = envelope["signature"]
    if not isinstance(signature, str) or not _SHA256.fullmatch(signature):
        raise ConfigError("Mutation attestation signature is invalid")
    if not hmac.compare_digest(signature, _signature(key, statement)):
        raise ConfigError("Mutation attestation signature verification failed")

    issued = _parse_timestamp(statement["issuedAt"], "issuedAt")
    expires = _parse_timestamp(statement["expiresAt"], "expiresAt")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if expires <= issued or (expires - issued).total_seconds() > max_ttl_seconds:
        raise ConfigError("Mutation attestation validity window is not allowed")
    skew = timedelta(seconds=clock_skew_seconds)
    if issued > current + skew:
        raise ConfigError("Mutation attestation is not yet valid")
    if expires < current - skew:
        raise ConfigError("Mutation attestation has expired")
    for name, value in expected.items():
        if statement.get(name) != value:
            raise ConfigError(f"Mutation attestation does not match {name}")
    return statement
