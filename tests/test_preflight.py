import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import grafana_alerts.cli as cli
from grafana_alerts.config import load_site
from grafana_alerts.exceptions import ConfigError
from grafana_alerts.preflight import run_preflight

runner = CliRunner()


class FakeClient:
    def __init__(self, *, org_id: int = 1, datasource_org_id: int = 1) -> None:
        self.org_id = org_id
        self.datasource_org_id = datasource_org_id

    def whoami(self) -> dict[str, str]:
        return {"login": "alert-deployer"}

    def current_org(self) -> dict[str, object]:
        return {"id": self.org_id, "name": "Main Org"}

    def get_folder(self, folder_uid: str) -> dict[str, str]:
        return {"uid": folder_uid, "title": "Infrastructure Alerts"}

    def get_datasource(self, datasource_uid: str) -> dict[str, object]:
        return {
            "uid": datasource_uid,
            "name": "Prometheus",
            "type": "prometheus",
            "orgId": self.datasource_org_id,
        }


def test_preflight_verifies_site_identity_and_resources() -> None:
    report = run_preflight(load_site("sites/example.yaml"), FakeClient())

    assert report.identity == "alert-deployer"
    assert report.org_id == 1
    assert report.folder_uid == "infrastructure-alerts"
    assert report.datasources[0].uid == "prometheus-main"


def test_preflight_rejects_token_from_wrong_organization() -> None:
    with pytest.raises(ConfigError, match="organization does not match"):
        run_preflight(load_site("sites/example.yaml"), FakeClient(org_id=2))


def test_preflight_rejects_datasource_from_wrong_organization() -> None:
    with pytest.raises(ConfigError, match="belongs to organization 2"):
        run_preflight(
            load_site("sites/example.yaml"), FakeClient(datasource_org_id=2)
        )


def test_preflight_checks_named_datasource_mapping(tmp_path: Path) -> None:
    raw = Path("sites/example.yaml").read_text(encoding="utf-8")
    raw = raw.replace(
        "datasource_uid: prometheus-main",
        "datasources:\n    prometheus: prometheus-main\n    loki: loki-main",
    )
    site_file = tmp_path / "mapping.yaml"
    site_file.write_text(raw, encoding="utf-8")
    requested: list[str] = []

    class MappingClient(FakeClient):
        def get_datasource(self, datasource_uid: str) -> dict[str, object]:
            requested.append(datasource_uid)
            return {
                "uid": datasource_uid,
                "name": datasource_uid,
                "type": "loki" if datasource_uid == "loki-main" else "prometheus",
                "orgId": 1,
            }

    report = run_preflight(load_site(site_file), MappingClient())

    assert requested == ["loki-main", "prometheus-main"]
    assert [item.key for item in report.datasources] == ["loki", "prometheus"]


def test_preflight_command_emits_machine_readable_report(monkeypatch) -> None:
    monkeypatch.setattr(cli, "GrafanaClient", lambda url, token: FakeClient())

    result = runner.invoke(
        cli.app,
        ["preflight", "sites/example.yaml", "--json"],
        env={"GRAFANA_URL": "https://grafana.example", "GRAFANA_TOKEN": "secret"},
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["site"] == "example"
    assert payload["org_id"] == 1
    assert payload["datasources"][0]["uid"] == "prometheus-main"
