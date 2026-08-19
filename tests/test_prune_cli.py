import json
from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

import grafana_alerts.cli as cli
from grafana_alerts.artifacts import write_bundle
from grafana_alerts.config import load_site
from grafana_alerts.deployment_plan import PruneCandidate, live_group_sha256, write_plan
from grafana_alerts.exceptions import GrafanaApiError
from grafana_alerts.receipt import load_and_verify_receipt
from grafana_alerts.renderer import render_site
from grafana_alerts.semantic import compare_group

runner = CliRunner()


class FakeGrafanaClient:
    def __init__(self, current: dict[str, object], *, fail_apply: bool = False) -> None:
        self.current = current
        self.fail_apply = fail_apply
        self.applied: list[str] = []
        self.deleted: list[str] = []

    def whoami(self) -> dict[str, str]:
        return {"login": "service-account"}

    def current_org(self) -> dict[str, object]:
        return {"id": 1, "name": "Main Org"}

    def get_folder(self, folder_uid: str) -> dict[str, object]:
        return {"uid": folder_uid, "title": "Infrastructure Alerts"}

    def get_datasource(self, datasource_uid: str) -> dict[str, object]:
        return {
            "uid": datasource_uid,
            "name": "Prometheus",
            "type": "prometheus",
            "orgId": 1,
        }

    def get_group(self, folder_uid: str, group: str) -> dict[str, object] | None:
        assert folder_uid == "infrastructure-alerts"
        return self.current if group == "retired" else None

    def apply_group(
        self, folder_uid: str, group: str, payload: dict[str, object]
    ) -> SimpleNamespace:
        if self.fail_apply:
            raise GrafanaApiError("Grafana rejected the rule group")
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
    receipt = tmp_path / "failure-receipt.json"
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
            "--receipt",
            str(receipt),
        ],
        env={"GRAFANA_URL": "https://grafana.example", "GRAFANA_TOKEN": "secret"},
    )

    assert result.exit_code == 1
    assert "PRUNE_ENABLED must equal true" in result.output
    assert fake.applied == []
    assert fake.deleted == []
    payload = load_and_verify_receipt(receipt)
    assert payload["status"] == "failed"
    assert payload["operations"] == []
    assert "PRUNE_ENABLED must equal true" in payload["error"]


def test_deploy_applies_artifact_then_deletes_exact_reviewed_group(
    tmp_path: Path, monkeypatch
) -> None:
    site_path, bundle, plan, current = _prune_inputs(tmp_path)
    fake = FakeGrafanaClient(current)
    receipt = tmp_path / "success-receipt.json"
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
            "--receipt",
            str(receipt),
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
    payload = load_and_verify_receipt(receipt)
    assert payload["status"] == "succeeded"
    assert payload["identity"] == "service-account"
    assert payload["artifactManifestSha256"]
    assert payload["deploymentPlanSha256"]
    assert [(item["action"], item["group"]) for item in payload["operations"]] == [
        ("apply", "host-health"),
        ("delete", "retired"),
    ]


def test_deploy_records_partial_failure_without_exposing_token(
    tmp_path: Path, monkeypatch
) -> None:
    site_path, bundle, _, current = _prune_inputs(tmp_path)
    fake = FakeGrafanaClient(current, fail_apply=True)
    monkeypatch.setattr(cli, "GrafanaClient", lambda url, token: fake)
    receipt = tmp_path / "apply-failure-receipt.json"

    result = runner.invoke(
        cli.app,
        [
            "deploy",
            str(site_path),
            "--artifact-dir",
            str(bundle.directory),
            "--receipt",
            str(receipt),
        ],
        env={"GRAFANA_URL": "https://grafana.example", "GRAFANA_TOKEN": "secret"},
    )

    assert result.exit_code == 1
    payload = load_and_verify_receipt(receipt)
    assert payload["status"] == "failed"
    assert payload["operations"] == [
        {
            "group": "host-health",
            "action": "apply",
            "status": "failed",
            "error": "Grafana rejected the rule group",
        }
    ]
    assert "secret" not in json.dumps(payload)
