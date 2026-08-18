from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

import grafana_alerts.cli as cli
from grafana_alerts.artifacts import write_bundle
from grafana_alerts.config import load_site
from grafana_alerts.deployment_plan import PruneCandidate, live_group_sha256, write_plan
from grafana_alerts.renderer import render_site
from grafana_alerts.semantic import compare_group

runner = CliRunner()


class FakeGrafanaClient:
    def __init__(self, current: dict[str, object]) -> None:
        self.current = current
        self.applied: list[str] = []
        self.deleted: list[str] = []

    def whoami(self) -> dict[str, str]:
        return {"login": "service-account"}

    def get_group(self, folder_uid: str, group: str) -> dict[str, object] | None:
        assert folder_uid == "infrastructure-alerts"
        return self.current if group == "retired" else None

    def apply_group(
        self, folder_uid: str, group: str, payload: dict[str, object]
    ) -> SimpleNamespace:
        self.applied.append(group)
        return SimpleNamespace(group=group, status_code=202)

    def delete_group(self, folder_uid: str, group: str) -> SimpleNamespace:
        self.deleted.append(group)
        return SimpleNamespace(group=group, status_code=204)


def _prune_inputs(tmp_path: Path):
    raw = Path("sites/example.yaml").read_text(encoding="utf-8")
    raw = raw.replace("allow_groups: []", 'allow_groups: ["retired"]')
    site_path = tmp_path / "site.yaml"
    site_path.write_text(raw, encoding="utf-8")
    site = load_site(site_path)
    rendered = render_site(site, "templates")
    bundle = write_bundle(site, rendered, tmp_path / "artifacts")
    comparisons = [
        compare_group(group.name, group.payload, group.payload) for group in rendered
    ]
    current = {"title": "retired", "rules": [{"uid": "old"}]}
    candidate = PruneCandidate("retired", live_group_sha256(current))
    plan = write_plan(comparisons, (candidate,), site, bundle, tmp_path / "plan")
    return site_path, bundle, plan, current


def test_deploy_refuses_prune_when_environment_gate_is_off(
    tmp_path: Path, monkeypatch
) -> None:
    site_path, bundle, plan, current = _prune_inputs(tmp_path)
    fake = FakeGrafanaClient(current)
    monkeypatch.setattr(cli, "GrafanaClient", lambda url, token: fake)

    result = runner.invoke(
        cli.app,
        [
            "deploy",
            str(site_path),
            "--artifact-dir",
            str(bundle.directory),
            "--prune-plan",
            str(plan),
            "--confirm-prune",
            "DELETE ALLOWLISTED GROUPS",
        ],
        env={"GRAFANA_URL": "https://grafana.example", "GRAFANA_TOKEN": "secret"},
    )

    assert result.exit_code == 1
    assert "PRUNE_ENABLED must equal true" in result.output
    assert fake.applied == []
    assert fake.deleted == []


def test_deploy_applies_artifact_then_deletes_exact_reviewed_group(
    tmp_path: Path, monkeypatch
) -> None:
    site_path, bundle, plan, current = _prune_inputs(tmp_path)
    fake = FakeGrafanaClient(current)
    monkeypatch.setattr(cli, "GrafanaClient", lambda url, token: fake)

    result = runner.invoke(
        cli.app,
        [
            "deploy",
            str(site_path),
            "--artifact-dir",
            str(bundle.directory),
            "--prune-plan",
            str(plan),
            "--confirm-prune",
            "DELETE ALLOWLISTED GROUPS",
        ],
        env={
            "GRAFANA_URL": "https://grafana.example",
            "GRAFANA_TOKEN": "secret",
            "PRUNE_ENABLED": "true",
        },
    )

    assert result.exit_code == 0, result.output
    assert fake.applied == ["host-health"]
    assert fake.deleted == ["retired"]
    assert "Deleted allowlisted group retired (HTTP 204)" in result.output
