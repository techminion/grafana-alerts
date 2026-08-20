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
    def __init__(
        self,
        current: dict[str, object],
        *,
        fail_apply: bool = False,
        fail_query: bool = False,
    ) -> None:
        self.current = current
        self.groups: dict[str, dict[str, object]] = {"retired": current}
        self.fail_apply = fail_apply
        self.fail_query = fail_query
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
        return self.groups.get(group)

    def apply_group(
        self, folder_uid: str, group: str, payload: dict[str, object]
    ) -> SimpleNamespace:
        if self.fail_apply:
            raise GrafanaApiError("Grafana rejected the rule group")
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
        if self.fail_query:
            raise GrafanaApiError("Prometheus rejected the deployed query")
        return {"resultType": "vector", "result": []}


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
    monkeypatch.setattr(cli, "_proxy_write_client", lambda *args: fake)

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
    monkeypatch.setattr(cli, "_proxy_write_client", lambda *args: fake)

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
    assert payload["verification"]["status"] == "succeeded"
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
    monkeypatch.setattr(cli, "_proxy_write_client", lambda *args: fake)
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


def test_deploy_refuses_direct_writes_when_proxy_is_not_configured(
    tmp_path: Path, monkeypatch
) -> None:
    site_path, bundle, _, current = _prune_inputs(tmp_path)
    fake = FakeGrafanaClient(current)
    monkeypatch.setattr(cli, "GrafanaClient", lambda url, token: fake)
    receipt = tmp_path / "missing-proxy-receipt.json"

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
    assert "ALERT_PROXY_URL must be set" in result.output
    assert fake.applied == []
    assert load_and_verify_receipt(receipt)["operations"] == []


def test_deploy_requires_pipeline_attestation_key(
    tmp_path: Path, monkeypatch
) -> None:
    site_path, bundle, _, current = _prune_inputs(tmp_path)
    fake = FakeGrafanaClient(current)
    monkeypatch.setattr(cli, "GrafanaClient", lambda url, token: fake)

    result = runner.invoke(
        cli.app,
        ["deploy", str(site_path), "--artifact-dir", str(bundle.directory)],
        env={
            "GRAFANA_URL": "https://grafana.example",
            "GRAFANA_TOKEN": "secret",
            "ALERT_PROXY_URL": "https://proxy.example",
        },
    )

    assert result.exit_code == 1
    assert "ALERT_ATTESTATION_KEY must be set" in result.output
    assert fake.applied == []


def test_deploy_fails_and_records_post_deployment_query_verification(
    tmp_path: Path, monkeypatch
) -> None:
    site_path, bundle, _, current = _prune_inputs(tmp_path)
    fake = FakeGrafanaClient(current, fail_query=True)
    monkeypatch.setattr(cli, "GrafanaClient", lambda url, token: fake)
    monkeypatch.setattr(cli, "_proxy_write_client", lambda *args: fake)
    receipt = tmp_path / "verification-failure-receipt.json"

    result = runner.invoke(
        cli.app,
        [
            "deploy",
            str(site_path),
            "--artifact-dir",
            str(bundle.directory),
            "--verification-attempts",
            "1",
            "--verification-delay",
            "0",
            "--receipt",
            str(receipt),
        ],
        env={"GRAFANA_URL": "https://grafana.example", "GRAFANA_TOKEN": "secret"},
    )

    assert result.exit_code == 1
    assert "Post-deployment verification failed" in result.output
    assert fake.applied == ["host-health"]
    payload = load_and_verify_receipt(receipt)
    assert payload["status"] == "failed"
    assert payload["verification"]["status"] == "failed"
    assert all(
        query["error"] == "Prometheus rejected the deployed query"
        for query in payload["verification"]["queries"]
    )
