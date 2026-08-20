from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote

from grafana_alerts.artifacts import ArtifactBundle
from grafana_alerts.config import SiteConfig
from grafana_alerts.deployment_plan import (
    artifact_manifest_sha256,
    live_group_sha256,
)
from grafana_alerts.exceptions import AlertManagerError, ConfigError
from grafana_alerts.receipt import utc_timestamp
from grafana_alerts.semantic import compare_group

DRIFT_SCHEMA_VERSION = 1


def _diff_filename(group: str) -> str:
    return f"{quote(group, safe='-_.')}.diff"


class DriftClient(Protocol):
    def get_group(self, folder_uid: str, group: str) -> dict[str, Any] | None: ...


@dataclass(frozen=True)
class DriftCheck:
    group: str
    target_state: str
    status: str
    desired_sha256: str | None = None
    live_sha256: str | None = None
    error: str | None = None
    diff: str = ""

    def payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "group": self.group,
            "targetState": self.target_state,
            "status": self.status,
            "desiredSha256": self.desired_sha256,
            "liveSha256": self.live_sha256,
        }
        if self.error is not None:
            payload["error"] = self.error
        if self.diff:
            payload["diffFile"] = _diff_filename(self.group)
        return payload


@dataclass(frozen=True)
class DriftReport:
    site: str
    org_id: int
    folder_uid: str
    identity: str
    artifact_manifest_sha256: str
    generated_at: str
    checks: tuple[DriftCheck, ...]

    @property
    def status(self) -> str:
        statuses = {check.status for check in self.checks}
        if "error" in statuses:
            return "error"
        if statuses & {"missing", "modified", "unexpected"}:
            return "drift"
        return "clean"

    def payload(self) -> dict[str, Any]:
        counts = {
            status: sum(check.status == status for check in self.checks)
            for status in (
                "in-sync",
                "absent",
                "missing",
                "modified",
                "unexpected",
                "error",
            )
        }
        return {
            "schemaVersion": DRIFT_SCHEMA_VERSION,
            "status": self.status,
            "generatedAt": self.generated_at,
            "site": self.site,
            "orgId": self.org_id,
            "folderUid": self.folder_uid,
            "identity": self.identity,
            "artifactManifestSha256": self.artifact_manifest_sha256,
            "summary": {"checked": len(self.checks), **counts},
            "groups": [check.payload() for check in self.checks],
        }


def detect_drift(
    site: SiteConfig,
    bundle: ArtifactBundle,
    identity: str,
    client: DriftClient,
) -> DriftReport:
    folder_uid = str(site.grafana["folder_uid"])
    checks: list[DriftCheck] = []
    desired_names = {group.name for group in bundle.groups}
    for group in bundle.groups:
        desired_sha256 = live_group_sha256(group.payload)
        try:
            current = client.get_group(folder_uid, group.name)
        except AlertManagerError as exc:
            checks.append(
                DriftCheck(
                    group.name,
                    "present",
                    "error",
                    desired_sha256=desired_sha256,
                    error=str(exc),
                )
            )
            continue
        if current is None:
            checks.append(
                DriftCheck(
                    group.name,
                    "present",
                    "missing",
                    desired_sha256=desired_sha256,
                )
            )
            continue
        comparison = compare_group(group.name, group.payload, current)
        checks.append(
            DriftCheck(
                group.name,
                "present",
                "in-sync" if comparison.action == "no-change" else "modified",
                desired_sha256=desired_sha256,
                live_sha256=live_group_sha256(current),
                diff=comparison.diff,
            )
        )

    for name in sorted(set(site.prune_allowlist) - desired_names):
        try:
            current = client.get_group(folder_uid, name)
        except AlertManagerError as exc:
            checks.append(DriftCheck(name, "absent", "error", error=str(exc)))
            continue
        checks.append(
            DriftCheck(
                name,
                "absent",
                "absent" if current is None else "unexpected",
                live_sha256=(
                    live_group_sha256(current) if current is not None else None
                ),
            )
        )

    return DriftReport(
        site=site.name,
        org_id=int(site.grafana["org_id"]),
        folder_uid=folder_uid,
        identity=identity,
        artifact_manifest_sha256=artifact_manifest_sha256(bundle),
        generated_at=utc_timestamp(),
        checks=tuple(checks),
    )


def write_drift_report(report: DriftReport, output_dir: str | Path) -> Path:
    directory = Path(output_dir)
    try:
        directory.mkdir(parents=True, exist_ok=True)
        report_path = directory / "drift-report.json"
        report_path.write_text(
            json.dumps(report.payload(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        for check in report.checks:
            if check.diff:
                (directory / _diff_filename(check.group)).write_text(
                    check.diff, encoding="utf-8"
                )
    except OSError as exc:
        raise ConfigError(f"Unable to write drift report: {exc}") from exc
    return report_path
