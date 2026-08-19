from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from grafana_alerts.artifacts import ArtifactBundle
from grafana_alerts.config import SiteConfig
from grafana_alerts.deployment_plan import artifact_manifest_sha256, live_group_sha256
from grafana_alerts.exceptions import ConfigError
from grafana_alerts.receipt import load_and_verify_receipt, sha256_file
from grafana_alerts.semantic import compare_group

ROLLBACK_PLAN_SCHEMA_VERSION = 1
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class GroupReader(Protocol):
    def get_group(self, folder_uid: str, group: str) -> dict[str, Any] | None: ...


@dataclass(frozen=True)
class RollbackAction:
    name: str
    target_state: str
    action: str
    live_sha256: str | None


@dataclass(frozen=True)
class RollbackPlan:
    path: Path
    reason: str
    source_receipt_sha256: str
    source_artifact_manifest_sha256: str
    target_artifact_manifest_sha256: str
    actions: tuple[RollbackAction, ...]


def _source_receipt(
    site: SiteConfig,
    source_receipt_file: str | Path,
) -> tuple[dict[str, Any], str]:
    receipt = load_and_verify_receipt(source_receipt_file)
    identity = (receipt["site"], receipt["orgId"], receipt["folderUid"])
    expected = (site.name, site.grafana["org_id"], site.grafana["folder_uid"])
    if identity != expected:
        raise ConfigError(
            "Source deployment receipt identity does not match the site config: "
            f"expected {expected}, found {identity}"
        )
    if receipt["status"] != "succeeded":
        raise ConfigError("Only a succeeded deployment receipt can be rolled back")
    artifact_hash = receipt["artifactManifestSha256"]
    if not isinstance(artifact_hash, str) or not _SHA256_PATTERN.fullmatch(artifact_hash):
        raise ConfigError("Source deployment receipt has no reviewed artifact fingerprint")
    return receipt, sha256_file(source_receipt_file)


def _source_applied_groups(receipt: dict[str, Any]) -> set[str]:
    return {
        operation["group"]
        for operation in receipt["operations"]
        if operation["action"] == "apply" and operation["status"] == "succeeded"
    }


def write_rollback_plan(
    site: SiteConfig,
    bundle: ArtifactBundle,
    source_receipt_file: str | Path,
    reason: str,
    client: GroupReader,
    output_dir: str | Path,
) -> Path:
    reason = reason.strip()
    if not reason:
        raise ConfigError("Rollback reason must not be empty")
    source_receipt, source_receipt_hash = _source_receipt(site, source_receipt_file)
    target_artifact_hash = artifact_manifest_sha256(bundle)
    source_artifact_hash = source_receipt["artifactManifestSha256"]
    if source_artifact_hash == target_artifact_hash:
        raise ConfigError("Rollback target artifact is identical to the source deployment")

    folder_uid = str(site.grafana["folder_uid"])
    target_names = {group.name for group in bundle.groups}
    actions: list[RollbackAction] = []
    for group in bundle.groups:
        current = client.get_group(folder_uid, group.name)
        comparison = compare_group(group.name, group.payload, current)
        actions.append(
            RollbackAction(
                name=group.name,
                target_state="present",
                action="no-change" if comparison.action == "no-change" else "apply",
                live_sha256=live_group_sha256(current) if current is not None else None,
            )
        )

    for name in sorted(_source_applied_groups(source_receipt) - target_names):
        current = client.get_group(folder_uid, name)
        actions.append(
            RollbackAction(
                name=name,
                target_state="absent",
                action="delete" if current is not None else "no-change",
                live_sha256=live_group_sha256(current) if current is not None else None,
            )
        )

    if not any(action.action != "no-change" for action in actions):
        raise ConfigError("Grafana already matches the rollback target")

    payload = {
        "schemaVersion": ROLLBACK_PLAN_SCHEMA_VERSION,
        "site": site.name,
        "orgId": site.grafana["org_id"],
        "folderUid": folder_uid,
        "reason": reason,
        "sourceReceiptSha256": source_receipt_hash,
        "sourceArtifactManifestSha256": source_artifact_hash,
        "targetArtifactManifestSha256": target_artifact_hash,
        "groups": [
            {
                "name": action.name,
                "targetState": action.target_state,
                "action": action.action,
                "liveSha256": action.live_sha256,
            }
            for action in actions
        ],
    }
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "rollback-plan.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def load_rollback_plan(
    site: SiteConfig,
    bundle: ArtifactBundle,
    source_receipt_file: str | Path,
    plan_file: str | Path,
) -> RollbackPlan:
    path = Path(plan_file).resolve()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Unable to read rollback plan {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("Rollback plan must contain a JSON object")

    required = {
        "schemaVersion",
        "site",
        "orgId",
        "folderUid",
        "reason",
        "sourceReceiptSha256",
        "sourceArtifactManifestSha256",
        "targetArtifactManifestSha256",
        "groups",
    }
    missing = required - raw.keys()
    if missing:
        raise ConfigError(f"Rollback plan is missing: {', '.join(sorted(missing))}")
    if raw["schemaVersion"] != ROLLBACK_PLAN_SCHEMA_VERSION:
        raise ConfigError(f"Unsupported rollback plan schema: {raw['schemaVersion']}")

    expected_identity = (site.name, site.grafana["org_id"], site.grafana["folder_uid"])
    plan_identity = (raw["site"], raw["orgId"], raw["folderUid"])
    if plan_identity != expected_identity:
        raise ConfigError(
            "Rollback plan identity does not match the site config: "
            f"expected {expected_identity}, found {plan_identity}"
        )
    if not isinstance(raw["reason"], str) or not raw["reason"].strip():
        raise ConfigError("Rollback plan reason must not be empty")

    source_receipt, source_receipt_hash = _source_receipt(site, source_receipt_file)
    if raw["sourceReceiptSha256"] != source_receipt_hash:
        raise ConfigError("Rollback plan does not match the source deployment receipt")
    if raw["sourceArtifactManifestSha256"] != source_receipt["artifactManifestSha256"]:
        raise ConfigError("Rollback plan source artifact does not match the deployment receipt")
    target_artifact_hash = artifact_manifest_sha256(bundle)
    if raw["targetArtifactManifestSha256"] != target_artifact_hash:
        raise ConfigError("Rollback plan does not match the reviewed target artifact")
    if raw["sourceArtifactManifestSha256"] == target_artifact_hash:
        raise ConfigError("Rollback target artifact is identical to the source deployment")

    if not isinstance(raw["groups"], list):
        raise ConfigError("Rollback plan groups must be a list")
    actions: list[RollbackAction] = []
    seen_names: set[str] = set()
    for entry in raw["groups"]:
        if not isinstance(entry, dict):
            raise ConfigError("Rollback plan contains an invalid group")
        name = entry.get("name")
        target_state = entry.get("targetState")
        action = entry.get("action")
        fingerprint = entry.get("liveSha256")
        if (
            not isinstance(name, str)
            or name in seen_names
            or target_state not in {"present", "absent"}
            or action not in {"apply", "delete", "no-change"}
            or (
                fingerprint is not None
                and (
                    not isinstance(fingerprint, str)
                    or not _SHA256_PATTERN.fullmatch(fingerprint)
                )
            )
        ):
            raise ConfigError("Rollback plan contains an invalid group")
        if target_state == "present" and action == "delete":
            raise ConfigError(f"Rollback plan cannot delete target group: {name}")
        if target_state == "absent" and action == "apply":
            raise ConfigError(f"Rollback plan cannot apply absent target group: {name}")
        seen_names.add(name)
        actions.append(RollbackAction(name, target_state, action, fingerprint))

    target_names = {group.name for group in bundle.groups}
    present_names = {action.name for action in actions if action.target_state == "present"}
    expected_absent = _source_applied_groups(source_receipt) - target_names
    absent_names = {action.name for action in actions if action.target_state == "absent"}
    if present_names != target_names or absent_names != expected_absent:
        raise ConfigError("Rollback plan groups do not match the complete rollback scope")
    if not any(action.action != "no-change" for action in actions):
        raise ConfigError("Rollback plan contains no changes")

    return RollbackPlan(
        path=path,
        reason=raw["reason"].strip(),
        source_receipt_sha256=source_receipt_hash,
        source_artifact_manifest_sha256=raw["sourceArtifactManifestSha256"],
        target_artifact_manifest_sha256=target_artifact_hash,
        actions=tuple(actions),
    )


def verify_live_rollback_plan(
    site: SiteConfig,
    plan: RollbackPlan,
    client: GroupReader,
) -> None:
    folder_uid = str(site.grafana["folder_uid"])
    for action in plan.actions:
        current = client.get_group(folder_uid, action.name)
        fingerprint = live_group_sha256(current) if current is not None else None
        if fingerprint != action.live_sha256:
            raise ConfigError(
                f"Rollback plan is stale; live group changed: {action.name}"
            )
