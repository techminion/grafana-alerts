from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from grafana_alerts.artifacts import ArtifactBundle
from grafana_alerts.config import SiteConfig
from grafana_alerts.exceptions import ConfigError
from grafana_alerts.semantic import Comparison, canonicalize

PLAN_SCHEMA_VERSION = 2
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class GroupReader(Protocol):
    def get_group(self, folder_uid: str, group: str) -> dict[str, Any] | None: ...


@dataclass(frozen=True)
class PruneCandidate:
    name: str
    live_sha256: str


@dataclass(frozen=True)
class DeploymentPlan:
    path: Path
    prune: tuple[PruneCandidate, ...]


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def artifact_manifest_sha256(bundle: ArtifactBundle) -> str:
    try:
        return _sha256((bundle.directory / "manifest.json").read_bytes())
    except OSError as exc:
        raise ConfigError(f"Unable to fingerprint artifact manifest: {exc}") from exc


def live_group_sha256(payload: dict[str, Any]) -> str:
    content = json.dumps(
        canonicalize(payload), sort_keys=True, separators=(",", ":")
    ).encode()
    return _sha256(content)


def collect_prune_candidates(
    site: SiteConfig,
    bundle: ArtifactBundle,
    client: GroupReader,
) -> tuple[PruneCandidate, ...]:
    desired_names = {group.name for group in bundle.groups}
    candidates: list[PruneCandidate] = []
    for name in sorted(site.prune_allowlist):
        if name in desired_names:
            continue
        current = client.get_group(site.grafana["folder_uid"], name)
        if current is not None:
            candidates.append(
                PruneCandidate(name=name, live_sha256=live_group_sha256(current))
            )
    return tuple(candidates)


def write_plan(
    comparisons: list[Comparison],
    prune: tuple[PruneCandidate, ...],
    site: SiteConfig,
    bundle: ArtifactBundle,
    output_dir: str | Path,
) -> Path:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    summary = {
        "schemaVersion": PLAN_SCHEMA_VERSION,
        "site": site.name,
        "orgId": site.grafana["org_id"],
        "folderUid": site.grafana["folder_uid"],
        "artifactManifestSha256": artifact_manifest_sha256(bundle),
        "groups": [
            {"name": comparison.group, "action": comparison.action}
            for comparison in comparisons
        ],
        "prune": [
            {"name": candidate.name, "liveSha256": candidate.live_sha256}
            for candidate in prune
        ],
    }
    summary_path = directory / "plan.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    for comparison in comparisons:
        if comparison.diff:
            (directory / f"{comparison.group}.diff").write_text(
                comparison.diff,
                encoding="utf-8",
            )
    return summary_path


def load_plan(
    site: SiteConfig,
    bundle: ArtifactBundle,
    plan_file: str | Path,
) -> DeploymentPlan:
    path = Path(plan_file).resolve()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Unable to read deployment plan {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("Deployment plan must contain a JSON object")

    required = {
        "schemaVersion",
        "site",
        "orgId",
        "folderUid",
        "artifactManifestSha256",
        "groups",
        "prune",
    }
    missing = required - raw.keys()
    if missing:
        raise ConfigError(f"Deployment plan is missing: {', '.join(sorted(missing))}")
    if raw["schemaVersion"] != PLAN_SCHEMA_VERSION:
        raise ConfigError(f"Unsupported deployment plan schema: {raw['schemaVersion']}")

    expected_identity = (site.name, site.grafana["org_id"], site.grafana["folder_uid"])
    plan_identity = (raw["site"], raw["orgId"], raw["folderUid"])
    if plan_identity != expected_identity:
        raise ConfigError(
            "Deployment plan identity does not match the site config: "
            f"expected {expected_identity}, found {plan_identity}"
        )
    if raw["artifactManifestSha256"] != artifact_manifest_sha256(bundle):
        raise ConfigError("Deployment plan does not match the reviewed artifact manifest")

    if not isinstance(raw["groups"], list):
        raise ConfigError("Deployment plan groups must be a list")
    plan_group_names: set[str] = set()
    for entry in raw["groups"]:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("name"), str)
            or entry.get("action") not in {"create", "update", "no-change"}
        ):
            raise ConfigError("Deployment plan contains an invalid group action")
        plan_group_names.add(entry["name"])
    desired_names = {group.name for group in bundle.groups}
    if plan_group_names != desired_names or len(raw["groups"]) != len(desired_names):
        raise ConfigError("Deployment plan groups do not match the reviewed artifact")

    if not isinstance(raw["prune"], list):
        raise ConfigError("Deployment plan prune must be a list")
    candidates: list[PruneCandidate] = []
    seen_names: set[str] = set()
    for entry in raw["prune"]:
        if not isinstance(entry, dict):
            raise ConfigError("Deployment plan contains an invalid prune entry")
        name = entry.get("name")
        fingerprint = entry.get("liveSha256")
        if not isinstance(name, str) or not isinstance(fingerprint, str):
            raise ConfigError("Deployment plan contains an invalid prune entry")
        if name in seen_names:
            raise ConfigError(f"Deployment plan contains duplicate prune group: {name}")
        if name not in site.prune_allowlist:
            raise ConfigError(f"Prune group is not allowlisted by the site config: {name}")
        if name in desired_names:
            raise ConfigError(f"Prune group is still present in the reviewed artifact: {name}")
        if not _SHA256_PATTERN.fullmatch(fingerprint):
            raise ConfigError(f"Prune group has an invalid live fingerprint: {name}")
        seen_names.add(name)
        candidates.append(PruneCandidate(name=name, live_sha256=fingerprint))
    return DeploymentPlan(path=path, prune=tuple(candidates))


def verify_live_prune_candidates(
    site: SiteConfig,
    plan: DeploymentPlan,
    client: GroupReader,
) -> None:
    for candidate in plan.prune:
        current = client.get_group(site.grafana["folder_uid"], candidate.name)
        if current is None:
            raise ConfigError(
                f"Prune plan is stale; group no longer exists: {candidate.name}"
            )
        if live_group_sha256(current) != candidate.live_sha256:
            raise ConfigError(
                f"Prune plan is stale; live group changed: {candidate.name}"
            )
