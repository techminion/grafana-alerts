from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import uvicorn
import yaml
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from grafana_alerts.attestation import (
    mutation_attestation_sha256,
    verify_mutation_attestation,
)
from grafana_alerts.config import SiteConfig, load_site
from grafana_alerts.deployment_plan import live_group_sha256
from grafana_alerts.exceptions import AlertManagerError, AuditConflictError, ConfigError
from grafana_alerts.grafana import GrafanaClient
from grafana_alerts.proxy_audit import AuditRecord, write_audit_record
from grafana_alerts.receipt import utc_timestamp
from grafana_alerts.validator import validate_group

_SITE_KEY = re.compile(r"^[A-Za-z0-9_-]+$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ROLES = {"Viewer", "Editor", "Admin"}
_IDENTITY_FIELDS = ("id", "login", "name", "email")
_BEARER = HTTPBearer(auto_error=False)
_BEARER_DEPENDENCY = Depends(_BEARER)


@dataclass(frozen=True)
class ProxySettings:
    grafana_url: str
    sites_dir: Path
    rbac_file: Path
    audit_dir: Path
    attestation_key: str
    attestation_max_ttl_seconds: int = 900


@dataclass(frozen=True)
class Authorization:
    identity: dict[str, str | int]
    role: str


class MutationContext(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    org_id: int = Field(alias="orgId")
    folder_uid: str = Field(alias="folderUid", min_length=1)
    artifact_manifest_sha256: str = Field(alias="artifactManifestSha256")
    pipeline: dict[str, str] = Field(default_factory=dict)
    attestation: dict[str, Any]


class ApplyRequest(MutationContext):
    payload: dict[str, Any]


class MutationResponse(BaseModel):
    group: str
    statusCode: int
    auditId: str
    auditSha256: str


ClientFactory = Callable[[str, str], GrafanaClient]
AuditWriter = Callable[[str | Path, str, str, dict[str, Any]], AuditRecord]


def _settings_from_env() -> ProxySettings:
    import os

    required = {
        "PROXY_GRAFANA_URL": os.getenv("PROXY_GRAFANA_URL", ""),
        "PROXY_RBAC_FILE": os.getenv("PROXY_RBAC_FILE", ""),
        "PROXY_AUDIT_DIR": os.getenv("PROXY_AUDIT_DIR", ""),
        "PROXY_ATTESTATION_KEY": os.getenv("PROXY_ATTESTATION_KEY", ""),
    }
    missing = [key for key, value in required.items() if not value.strip()]
    if missing:
        raise ConfigError(f"Proxy configuration is missing: {', '.join(missing)}")
    try:
        max_ttl_seconds = int(
            os.getenv("PROXY_ATTESTATION_MAX_TTL_SECONDS", "900")
        )
    except ValueError as exc:
        raise ConfigError("PROXY_ATTESTATION_MAX_TTL_SECONDS must be an integer") from exc
    if max_ttl_seconds < 1:
        raise ConfigError("PROXY_ATTESTATION_MAX_TTL_SECONDS must be positive")
    if len(required["PROXY_ATTESTATION_KEY"].encode()) < 32:
        raise ConfigError("PROXY_ATTESTATION_KEY must be at least 32 bytes")
    return ProxySettings(
        grafana_url=required["PROXY_GRAFANA_URL"],
        sites_dir=Path(os.getenv("PROXY_SITES_DIR", "sites")),
        rbac_file=Path(required["PROXY_RBAC_FILE"]),
        audit_dir=Path(required["PROXY_AUDIT_DIR"]),
        attestation_key=required["PROXY_ATTESTATION_KEY"],
        attestation_max_ttl_seconds=max_ttl_seconds,
    )


def _trusted_identity(raw: dict[str, Any]) -> dict[str, str | int]:
    identity = {
        key: value
        for key in _IDENTITY_FIELDS
        if isinstance((value := raw.get(key)), (str, int)) and str(value).strip()
    }
    if not identity:
        raise ConfigError("Grafana /api/user did not return a usable identity")
    return identity


def _load_rbac(path: Path) -> list[dict[str, Any]]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"Unable to read proxy RBAC config {path}: {exc}") from exc
    if not isinstance(raw, dict) or raw.get("schemaVersion") != 1:
        raise ConfigError("Proxy RBAC config must use schemaVersion 1")
    identities = raw.get("identities")
    if not isinstance(identities, list):
        raise ConfigError("Proxy RBAC identities must be a list")
    for entry in identities:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("match"), dict)
            or not entry["match"]
            or not set(entry["match"]).issubset(_IDENTITY_FIELDS)
            or entry.get("role") not in _ROLES
            or not isinstance(entry.get("sites"), list)
            or not all(isinstance(site, str) and site for site in entry["sites"])
        ):
            raise ConfigError("Proxy RBAC config contains an invalid identity entry")
        if not all(isinstance(value, (str, int)) for value in entry["match"].values()):
            raise ConfigError("Proxy RBAC identity match values must be strings or integers")
    return identities


def _authorize(
    settings: ProxySettings,
    token: str,
    site_key: str,
    org_id: int,
    client_factory: ClientFactory,
) -> tuple[Authorization, GrafanaClient]:
    client = client_factory(settings.grafana_url, token)
    identity = _trusted_identity(client.whoami())
    current_org = client.current_org()
    if current_org.get("id") != org_id:
        raise HTTPException(status_code=403, detail="Grafana token organization is not authorized")

    matches = []
    for entry in _load_rbac(settings.rbac_file):
        if all(identity.get(key) == value for key, value in entry["match"].items()):
            matches.append(entry)
    if len(matches) != 1:
        raise HTTPException(status_code=403, detail="Grafana identity has no unique proxy role")
    entry = matches[0]
    if site_key not in entry["sites"] and "*" not in entry["sites"]:
        raise HTTPException(
            status_code=403,
            detail="Grafana identity is not authorized for this site",
        )
    return Authorization(identity, entry["role"]), client


def _load_target(settings: ProxySettings, site_key: str) -> SiteConfig:
    if not _SITE_KEY.fullmatch(site_key):
        raise HTTPException(status_code=404, detail="Unknown site")
    base = settings.sites_dir.resolve()
    path = (base / f"{site_key}.yaml").resolve()
    if path.parent != base or not path.is_file():
        raise HTTPException(status_code=404, detail="Unknown site")
    return load_site(path)


def _validate_context(site: SiteConfig, request: MutationContext) -> None:
    if request.org_id != site.grafana["org_id"]:
        raise HTTPException(status_code=409, detail="Request organization does not match site")
    if request.folder_uid != str(site.grafana["folder_uid"]):
        raise HTTPException(status_code=409, detail="Request folder does not match site")
    if not _SHA256.fullmatch(request.artifact_manifest_sha256):
        raise HTTPException(status_code=422, detail="Invalid artifact manifest fingerprint")


def _validate_payload(site: SiteConfig, group: str, payload: dict[str, Any]) -> None:
    try:
        validate_group(payload)
    except ConfigError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if payload.get("title") != group:
        raise HTTPException(status_code=409, detail="Payload title does not match group path")
    if payload.get("folderUid") != str(site.grafana["folder_uid"]):
        raise HTTPException(status_code=409, detail="Payload folder does not match site")
    for rule in payload["rules"]:
        if (
            rule.get("folderUID") != str(site.grafana["folder_uid"])
            or rule.get("orgId") != site.grafana["org_id"]
            or rule.get("ruleGroup") != group
        ):
            raise HTTPException(status_code=409, detail="Payload rule target does not match site")


def _verify_attestation(
    settings: ProxySettings,
    request: MutationContext,
    site_key: str,
    group: str,
    operation: str,
    *,
    payload_sha256: str | None,
    expected_before_sha256: str | None,
) -> dict[str, Any]:
    expected = {
        "site": site_key,
        "orgId": request.org_id,
        "folderUid": request.folder_uid,
        "group": group,
        "operation": operation,
        "artifactManifestSha256": request.artifact_manifest_sha256,
        "payloadSha256": payload_sha256,
        "expectedBeforeSha256": expected_before_sha256,
    }
    try:
        return verify_mutation_attestation(
            request.attestation,
            settings.attestation_key,
            expected=expected,
            max_ttl_seconds=settings.attestation_max_ttl_seconds,
        )
    except ConfigError as exc:
        raise HTTPException(
            status_code=403, detail=f"Mutation attestation rejected: {exc}"
        ) from exc


def _audit_payload(
    request_id: str,
    phase: str,
    auth: Authorization,
    request: MutationContext,
    site_key: str,
    group: str,
    action: str,
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
    *,
    status: str,
    http_status: int | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schemaVersion": 1,
        "requestId": request_id,
        "phase": phase,
        "timestamp": utc_timestamp(),
        "identity": auth.identity,
        "role": auth.role,
        "site": site_key,
        "orgId": request.org_id,
        "folderUid": request.folder_uid,
        "group": group,
        "action": action,
        "artifactManifestSha256": request.artifact_manifest_sha256,
        "attestationSha256": mutation_attestation_sha256(request.attestation),
        "before": before,
        "beforeSha256": live_group_sha256(before) if before is not None else None,
        "after": after,
        "afterSha256": live_group_sha256(after) if after is not None else None,
        "clientPipeline": request.pipeline,
        "status": status,
    }
    if http_status is not None:
        payload["httpStatus"] = http_status
    if error is not None:
        payload["error"] = error
    return payload


def _require_action(role: str, action: str) -> None:
    allowed = {
        "Viewer": set(),
        "Editor": {"create"},
        "Admin": {"create", "update", "delete"},
    }
    if action not in allowed[role]:
        raise HTTPException(status_code=403, detail=f"{role} role cannot {action} rule groups")


def create_app(
    settings: ProxySettings | None = None,
    *,
    client_factory: ClientFactory = GrafanaClient,
    audit_writer: AuditWriter = write_audit_record,
) -> FastAPI:
    app = FastAPI(title="Grafana Alerts Change-Control Proxy", version="1.0")

    @app.exception_handler(AlertManagerError)
    def alert_manager_error(_request: Any, exc: AlertManagerError) -> JSONResponse:
        return JSONResponse(status_code=502, content={"detail": str(exc)})

    def configured() -> ProxySettings:
        try:
            return settings or _settings_from_env()
        except ConfigError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    def token(credentials: HTTPAuthorizationCredentials | None) -> str:
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Grafana bearer token is required")
        return credentials.credentials

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        configured()
        return {"status": "ok"}

    @app.put("/v1/sites/{site_key}/groups/{group}", response_model=MutationResponse)
    def apply_group(
        site_key: str,
        group: str,
        request: ApplyRequest,
        credentials: HTTPAuthorizationCredentials | None = _BEARER_DEPENDENCY,
    ) -> MutationResponse:
        return _apply(site_key, group, request, credentials)

    def _apply(
        site_key: str,
        group: str,
        request: ApplyRequest,
        credentials: HTTPAuthorizationCredentials | None,
    ) -> MutationResponse:
        proxy_settings = configured()
        site = _load_target(proxy_settings, site_key)
        _validate_context(site, request)
        _validate_payload(site, group, request.payload)
        desired_sha256 = live_group_sha256(request.payload)
        attestation = _verify_attestation(
            proxy_settings,
            request,
            site_key,
            group,
            "apply",
            payload_sha256=desired_sha256,
            expected_before_sha256=None,
        )
        auth, client = _authorize(
            proxy_settings, token(credentials), site_key, request.org_id, client_factory
        )
        before = client.get_group(request.folder_uid, group)
        action = "create" if before is None else "update"
        _require_action(auth.role, action)
        request_id = attestation["nonce"]
        intent = _audit_payload(
            request_id,
            "intent",
            auth,
            request,
            site_key,
            group,
            action,
            before,
            request.payload,
            status="pending",
        )
        try:
            audit_writer(proxy_settings.audit_dir, request_id, "intent", intent)
        except AuditConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ConfigError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        try:
            result = client.apply_group(request.folder_uid, group, request.payload)
        except AlertManagerError as exc:
            outcome = _audit_payload(
                request_id,
                "outcome",
                auth,
                request,
                site_key,
                group,
                action,
                before,
                request.payload,
                status="failed",
                error=str(exc),
            )
            audit = audit_writer(proxy_settings.audit_dir, request_id, "outcome", outcome)
            raise HTTPException(
                status_code=502,
                detail={
                    "message": str(exc),
                    "auditId": request_id,
                    "auditSha256": audit.sha256,
                },
            ) from exc
        outcome = _audit_payload(
            request_id,
            "outcome",
            auth,
            request,
            site_key,
            group,
            action,
            before,
            request.payload,
            status="succeeded",
            http_status=result.status_code,
        )
        audit = audit_writer(proxy_settings.audit_dir, request_id, "outcome", outcome)
        return MutationResponse(
            group=group,
            statusCode=result.status_code,
            auditId=request_id,
            auditSha256=audit.sha256,
        )

    @app.post(
        "/v1/sites/{site_key}/groups/{group}:delete",
        response_model=MutationResponse,
    )
    def delete_group(
        site_key: str,
        group: str,
        request: MutationContext,
        credentials: HTTPAuthorizationCredentials | None = _BEARER_DEPENDENCY,
    ) -> MutationResponse:
        proxy_settings = configured()
        site = _load_target(proxy_settings, site_key)
        _validate_context(site, request)
        auth, client = _authorize(
            proxy_settings, token(credentials), site_key, request.org_id, client_factory
        )
        before = client.get_group(request.folder_uid, group)
        if before is None:
            raise HTTPException(status_code=404, detail="Rule group does not exist")
        before_sha256 = live_group_sha256(before)
        attestation = _verify_attestation(
            proxy_settings,
            request,
            site_key,
            group,
            "delete",
            payload_sha256=None,
            expected_before_sha256=before_sha256,
        )
        _require_action(auth.role, "delete")
        request_id = attestation["nonce"]
        intent = _audit_payload(
            request_id,
            "intent",
            auth,
            request,
            site_key,
            group,
            "delete",
            before,
            None,
            status="pending",
        )
        try:
            audit_writer(proxy_settings.audit_dir, request_id, "intent", intent)
        except AuditConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ConfigError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        try:
            result = client.delete_group(request.folder_uid, group)
        except AlertManagerError as exc:
            outcome = _audit_payload(
                request_id,
                "outcome",
                auth,
                request,
                site_key,
                group,
                "delete",
                before,
                None,
                status="failed",
                error=str(exc),
            )
            audit = audit_writer(proxy_settings.audit_dir, request_id, "outcome", outcome)
            raise HTTPException(
                status_code=502,
                detail={
                    "message": str(exc),
                    "auditId": request_id,
                    "auditSha256": audit.sha256,
                },
            ) from exc
        outcome = _audit_payload(
            request_id,
            "outcome",
            auth,
            request,
            site_key,
            group,
            "delete",
            before,
            None,
            status="succeeded",
            http_status=result.status_code,
        )
        audit = audit_writer(proxy_settings.audit_dir, request_id, "outcome", outcome)
        return MutationResponse(
            group=group,
            statusCode=result.status_code,
            auditId=request_id,
            auditSha256=audit.sha256,
        )

    return app


app = create_app()


def run() -> None:
    uvicorn.run("grafana_alerts.proxy_app:app", host="0.0.0.0", port=8080)
