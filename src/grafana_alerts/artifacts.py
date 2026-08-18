from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from grafana_alerts.config import SiteConfig
from grafana_alerts.exceptions import ConfigError
from grafana_alerts.renderer import RenderedGroup
from grafana_alerts.validator import validate_group

SCHEMA_VERSION = 1


@dataclass(frozen=True)
class ArtifactGroup:
    name: str
    filename: str
    sha256: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class ArtifactBundle:
    directory: Path
    site: str
    org_id: int
    folder_uid: str
    groups: tuple[ArtifactGroup, ...]


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()


def _digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def write_bundle(
    site: SiteConfig,
    groups: Iterable[RenderedGroup],
    output_dir: str | Path,
) -> ArtifactBundle:
    directory = Path(output_dir) / site.name
    directory.mkdir(parents=True, exist_ok=True)
    artifacts: list[ArtifactGroup] = []

    for group in groups:
        filename = f"{group.name}.json"
        content = _json_bytes(group.payload)
        (directory / filename).write_bytes(content)
        artifacts.append(
            ArtifactGroup(
                name=group.name,
                filename=filename,
                sha256=_digest(content),
                payload=group.payload,
            )
        )

    manifest = {
        "schemaVersion": SCHEMA_VERSION,
        "site": site.name,
        "orgId": site.grafana["org_id"],
        "folderUid": site.grafana["folder_uid"],
        "groups": [
            {"name": group.name, "file": group.filename, "sha256": group.sha256}
            for group in artifacts
        ],
    }
    (directory / "manifest.json").write_bytes(_json_bytes(manifest))
    return ArtifactBundle(
        directory=directory,
        site=site.name,
        org_id=site.grafana["org_id"],
        folder_uid=site.grafana["folder_uid"],
        groups=tuple(artifacts),
    )


def _load_json(path: Path, description: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Unable to read {description} {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ConfigError(f"{description} must contain a JSON object: {path}")
    return payload


def load_bundle(site: SiteConfig, artifact_dir: str | Path) -> ArtifactBundle:
    directory = Path(artifact_dir).resolve()
    if not (directory / "manifest.json").is_file() and (
        directory / site.name / "manifest.json"
    ).is_file():
        directory = directory / site.name
    manifest = _load_json(directory / "manifest.json", "artifact manifest")
    required = {"schemaVersion", "site", "orgId", "folderUid", "groups"}
    missing = required - manifest.keys()
    if missing:
        raise ConfigError(f"Artifact manifest is missing: {', '.join(sorted(missing))}")
    if manifest["schemaVersion"] != SCHEMA_VERSION:
        raise ConfigError(f"Unsupported artifact schema version: {manifest['schemaVersion']}")

    expected_identity = (site.name, site.grafana["org_id"], site.grafana["folder_uid"])
    artifact_identity = (manifest["site"], manifest["orgId"], manifest["folderUid"])
    if artifact_identity != expected_identity:
        raise ConfigError(
            "Artifact identity does not match the site config: "
            f"expected {expected_identity}, found {artifact_identity}"
        )
    if not isinstance(manifest["groups"], list):
        raise ConfigError("Artifact manifest groups must be a list")

    expected_names = {group.name for group in site.groups}
    artifacts: list[ArtifactGroup] = []
    seen_names: set[str] = set()
    for index, entry in enumerate(manifest["groups"]):
        if not isinstance(entry, dict) or not {"name", "file", "sha256"} <= entry.keys():
            raise ConfigError(f"Invalid artifact manifest group at index {index}")
        name, filename, expected_hash = entry["name"], entry["file"], entry["sha256"]
        if name in seen_names:
            raise ConfigError(f"Duplicate artifact group: {name}")
        seen_names.add(name)

        path = (directory / filename).resolve()
        if path.parent != directory or path.name != filename:
            raise ConfigError(f"Unsafe artifact filename: {filename}")
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise ConfigError(f"Unable to read artifact {path}: {exc}") from exc
        actual_hash = _digest(content)
        if actual_hash != expected_hash:
            raise ConfigError(
                f"Artifact hash mismatch for {filename}: expected {expected_hash}, "
                f"found {actual_hash}"
            )
        payload = _load_json(path, "rule group artifact")
        validate_group(payload)
        if payload.get("title") != name:
            raise ConfigError(f"Artifact {filename} title does not match manifest group {name}")
        artifacts.append(
            ArtifactGroup(
                name=name,
                filename=filename,
                sha256=actual_hash,
                payload=payload,
            )
        )

    if seen_names != expected_names:
        missing_names = expected_names - seen_names
        extra_names = seen_names - expected_names
        details = []
        if missing_names:
            details.append(f"missing {', '.join(sorted(missing_names))}")
        if extra_names:
            details.append(f"unexpected {', '.join(sorted(extra_names))}")
        raise ConfigError(f"Artifact groups do not match site config: {'; '.join(details)}")

    return ArtifactBundle(
        directory=directory,
        site=manifest["site"],
        org_id=manifest["orgId"],
        folder_uid=manifest["folderUid"],
        groups=tuple(artifacts),
    )
