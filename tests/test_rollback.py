import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import grafana_alerts.cli as cli
from grafana_alerts.artifacts import write_bundle
from grafana_alerts.config import load_site
from grafana_alerts.exceptions import ConfigError
from grafana_alerts.receipt import ReceiptRecorder, load_and_verify_receipt, write_receipt
from grafana_alerts.renderer import render_site
from grafana_alerts.rollback import (
    load_rollback_plan,
    verify_live_rollback_plan,
    write_rollback_plan,
)

runner = CliRunner()


class FakeGrafanaClient:
    def __init__(self) -> None:
        self.groups: dict[str, dict[str, object]] = {
            "host-health": {
                "title": "host-health",
                "rules": [{"uid": "changed", "condition": "B"}],
            },
            "introduced-group": {
                "title": "introduced-group",
                "rules": [{"uid": "introduced"}],
            },
        }
        self.applied: list[str] = []
        self.deleted: list[str] = []

    def whoami(self) -> dict[str, str]:
        return {"login": "rollback-service"}

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
        return self.groups.get(group)

    def apply_group(
        self, folder_uid: str, group: str, payload: dict[str, object]
    ) -> SimpleNamespace:
        self.applied.append(group)
        self.groups[group] = payload
        return SimpleNamespace(
            group=group, status_code=202, audit_id="audit-apply", audit_sha256="a" * 64
        )

    def delete_group(
        self, folder_uid: str, group: str, expected_before_sha256: str
    ) -> SimpleNamespace:
        assert expected_before_sha256
        self.deleted.append(group)
        self.groups.pop(group, None)
        return SimpleNamespace(
            group=group, status_code=204, audit_id="audit-delete", audit_sha256="b" * 64
        )

    def query_prometheus(
        self, datasource_uid: str, expression: str, *, time: str | None = None
    ) -> dict[str, object]:
        return {"resultType": "vector", "result": []}


def _rollback_inputs(tmp_path: Path):
    site_path = Path("sites/example.yaml")
    site = load_site(site_path)
    bundle = write_bundle(
        site,
        render_site(site, "templates"),
        tmp_path / "target-artifact",
    )
    source_receipt = tmp_path / "source-receipt.json"
    recorder = ReceiptRecorder(
        started_at="2026-08-19T10:00:00Z",
        pipeline={"buildId": "41", "sourceVersion": "bad-commit"},
    )
    recorder.target(site.name, site.grafana["org_id"], site.grafana["folder_uid"])
    recorder.identity = "deployment-service"
    recorder.artifact_manifest_sha256 = "c" * 64
    recorder.record("host-health", "apply", "succeeded", http_status=202)
    recorder.record("introduced-group", "apply", "succeeded", http_status=202)
    write_receipt(source_receipt, recorder.payload("succeeded"))
    return site_path, site, bundle, source_receipt


def test_rollback_plan_binds_live_state_and_complete_source_scope(tmp_path: Path) -> None:
    _, site, bundle, source_receipt = _rollback_inputs(tmp_path)
    fake = FakeGrafanaClient()

    path = write_rollback_plan(
        site,
        bundle,
        source_receipt,
        "Revert alert regression",
        fake,
        tmp_path / "plan",
    )
    plan = load_rollback_plan(site, bundle, source_receipt, path)

    assert plan.reason == "Revert alert regression"
    assert [(item.name, item.target_state, item.action) for item in plan.actions] == [
        ("host-health", "present", "apply"),
        ("introduced-group", "absent", "delete"),
    ]
    verify_live_rollback_plan(site, plan, fake)


def test_rollback_plan_rejects_live_drift(tmp_path: Path) -> None:
    _, site, bundle, source_receipt = _rollback_inputs(tmp_path)
    fake = FakeGrafanaClient()
    path = write_rollback_plan(
        site, bundle, source_receipt, "Revert regression", fake, tmp_path / "plan"
    )
    plan = load_rollback_plan(site, bundle, source_receipt, path)
    fake.groups["introduced-group"] = {"title": "introduced-group", "rules": []}

    with pytest.raises(ConfigError, match="plan is stale"):
        verify_live_rollback_plan(site, plan, fake)


def test_rollback_plan_rejects_incomplete_delete_scope(tmp_path: Path) -> None:
    _, site, bundle, source_receipt = _rollback_inputs(tmp_path)
    fake = FakeGrafanaClient()
    path = write_rollback_plan(
        site, bundle, source_receipt, "Revert regression", fake, tmp_path / "plan"
    )
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["groups"] = [entry for entry in raw["groups"] if entry["targetState"] == "present"]
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(ConfigError, match="complete rollback scope"):
        load_rollback_plan(site, bundle, source_receipt, path)


def test_rollback_requires_environment_gate_and_writes_failure_receipt(
    tmp_path: Path, monkeypatch
) -> None:
    site_path, site, bundle, source_receipt = _rollback_inputs(tmp_path)
    fake = FakeGrafanaClient()
    monkeypatch.setattr(cli, "GrafanaClient", lambda url, token: fake)
    monkeypatch.setattr(cli, "_proxy_write_client", lambda *args: fake)
    plan = write_rollback_plan(
        site, bundle, source_receipt, "Revert regression", fake, tmp_path / "plan"
    )
    receipt = tmp_path / "rollback-failed.json"

    result = runner.invoke(
        cli.app,
        [
            "rollback",
            str(site_path),
            "--artifact-dir",
            str(bundle.directory),
            "--source-receipt",
            str(source_receipt),
            "--plan",
            str(plan),
            "--confirm-rollback",
            "ROLL BACK REVIEWED ARTIFACT",
            "--receipt",
            str(receipt),
        ],
        env={"GRAFANA_URL": "https://grafana.example", "GRAFANA_TOKEN": "secret"},
    )

    assert result.exit_code == 1
    assert "ROLLBACK_ENABLED must equal true" in result.output
    assert fake.applied == []
    assert fake.deleted == []
    payload = load_and_verify_receipt(receipt)
    assert payload["status"] == "failed"
    assert payload["rollback"]["reason"] == "Revert regression"


def test_rollback_restores_target_and_removes_introduced_group(
    tmp_path: Path, monkeypatch
) -> None:
    site_path, site, bundle, source_receipt = _rollback_inputs(tmp_path)
    fake = FakeGrafanaClient()
    monkeypatch.setattr(cli, "GrafanaClient", lambda url, token: fake)
    monkeypatch.setattr(cli, "_proxy_write_client", lambda *args: fake)
    plan = write_rollback_plan(
        site, bundle, source_receipt, "Revert regression", fake, tmp_path / "plan"
    )
    receipt = tmp_path / "rollback-succeeded.json"

    result = runner.invoke(
        cli.app,
        [
            "rollback",
            str(site_path),
            "--artifact-dir",
            str(bundle.directory),
            "--source-receipt",
            str(source_receipt),
            "--plan",
            str(plan),
            "--confirm-rollback",
            "ROLL BACK REVIEWED ARTIFACT",
            "--receipt",
            str(receipt),
        ],
        env={
            "GRAFANA_URL": "https://grafana.example",
            "GRAFANA_TOKEN": "secret",
            "ROLLBACK_ENABLED": "true",
        },
    )

    assert result.exit_code == 0, result.output
    assert fake.applied == ["host-health"]
    assert fake.deleted == ["introduced-group"]
    payload = load_and_verify_receipt(receipt)
    assert payload["status"] == "succeeded"
    assert payload["identity"] == "rollback-service"
    assert payload["rollback"]["reason"] == "Revert regression"
    assert payload["verification"]["status"] == "succeeded"
    assert [(item["action"], item["group"]) for item in payload["operations"]] == [
        ("apply", "host-health"),
        ("delete", "introduced-group"),
    ]
