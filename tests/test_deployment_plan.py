import json
from pathlib import Path

import pytest

from grafana_alerts.artifacts import write_bundle
from grafana_alerts.config import load_site
from grafana_alerts.deployment_plan import (
    PruneCandidate,
    collect_prune_candidates,
    live_group_sha256,
    load_plan,
    verify_live_prune_candidates,
    write_plan,
)
from grafana_alerts.exceptions import ConfigError
from grafana_alerts.renderer import render_site
from grafana_alerts.semantic import compare_group


class FakeClient:
    def __init__(self, groups: dict[str, dict[str, object]]) -> None:
        self.groups = groups
        self.requests: list[tuple[str, str]] = []

    def get_group(self, folder_uid: str, group: str) -> dict[str, object] | None:
        self.requests.append((folder_uid, group))
        return self.groups.get(group)


def _site_with_allowlist(tmp_path: Path, names: list[str]):
    raw = Path("sites/example.yaml").read_text(encoding="utf-8")
    raw = raw.replace("allow_groups: []", f"allow_groups: {json.dumps(names)}")
    site_file = tmp_path / "site.yaml"
    site_file.write_text(raw, encoding="utf-8")
    return load_site(site_file)


def _bundle_and_comparisons(site, tmp_path: Path):
    rendered = render_site(site, "templates")
    bundle = write_bundle(site, rendered, tmp_path / "artifacts")
    comparisons = [
        compare_group(group.name, group.payload, group.payload) for group in rendered
    ]
    return bundle, comparisons


def test_collect_prune_candidates_probes_only_absent_allowlisted_groups(
    tmp_path: Path,
) -> None:
    site = _site_with_allowlist(tmp_path, ["host-health", "retired", "not-live"])
    bundle, _ = _bundle_and_comparisons(site, tmp_path)
    retired = {"title": "retired", "rules": [{"uid": "old"}]}
    client = FakeClient({"retired": retired})

    candidates = collect_prune_candidates(site, bundle, client)

    assert candidates == (
        PruneCandidate(name="retired", live_sha256=live_group_sha256(retired)),
    )
    assert client.requests == [
        ("infrastructure-alerts", "not-live"),
        ("infrastructure-alerts", "retired"),
    ]


def test_plan_binds_pruning_to_site_artifact_and_live_fingerprint(
    tmp_path: Path,
) -> None:
    site = _site_with_allowlist(tmp_path, ["retired"])
    bundle, comparisons = _bundle_and_comparisons(site, tmp_path)
    current = {"title": "retired", "rules": [{"uid": "old"}]}
    candidate = PruneCandidate("retired", live_group_sha256(current))
    plan_path = write_plan(comparisons, (candidate,), site, bundle, tmp_path / "plan")

    plan = load_plan(site, bundle, plan_path)

    assert plan.prune == (candidate,)
    raw = json.loads(plan_path.read_text(encoding="utf-8"))
    assert raw["schemaVersion"] == 2
    assert raw["folderUid"] == "infrastructure-alerts"
    assert len(raw["artifactManifestSha256"]) == 64


def test_plan_rejects_non_allowlisted_prune_group(tmp_path: Path) -> None:
    site = _site_with_allowlist(tmp_path, ["retired"])
    bundle, comparisons = _bundle_and_comparisons(site, tmp_path)
    candidate = PruneCandidate("retired", "a" * 64)
    plan_path = write_plan(comparisons, (candidate,), site, bundle, tmp_path / "plan")
    raw = json.loads(plan_path.read_text(encoding="utf-8"))
    raw["prune"][0]["name"] = "surprise"
    plan_path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(ConfigError, match="not allowlisted"):
        load_plan(site, bundle, plan_path)


def test_plan_rejects_different_artifact(tmp_path: Path) -> None:
    site = _site_with_allowlist(tmp_path, ["retired"])
    bundle, comparisons = _bundle_and_comparisons(site, tmp_path)
    plan_path = write_plan(comparisons, (), site, bundle, tmp_path / "plan")
    manifest_path = bundle.directory / "manifest.json"
    manifest_path.write_text(manifest_path.read_text() + "\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="reviewed artifact manifest"):
        load_plan(site, bundle, plan_path)


def test_live_group_must_match_reviewed_prune_fingerprint(tmp_path: Path) -> None:
    site = _site_with_allowlist(tmp_path, ["retired"])
    bundle, comparisons = _bundle_and_comparisons(site, tmp_path)
    original = {"title": "retired", "rules": [{"uid": "old"}]}
    candidate = PruneCandidate("retired", live_group_sha256(original))
    plan_path = write_plan(comparisons, (candidate,), site, bundle, tmp_path / "plan")
    plan = load_plan(site, bundle, plan_path)
    client = FakeClient(
        {"retired": {"title": "retired", "rules": [{"uid": "changed"}]}}
    )

    with pytest.raises(ConfigError, match="live group changed"):
        verify_live_prune_candidates(site, plan, client)
