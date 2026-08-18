from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

import grafana_alerts.cli as cli
from grafana_alerts.builder import (
    AlertDefinition,
    generated_uid,
    prometheus_selector,
    write_site_with_alert,
)
from grafana_alerts.config import load_site
from grafana_alerts.exceptions import ConfigError
from grafana_alerts.renderer import render_site

runner = CliRunner()


def _definition(**overrides: object) -> AlertDefinition:
    values = {
        "group_name": "generated-api-down",
        "uid": "api-down",
        "title": "API down",
        "datasource_uid": "prometheus-main",
        "expression": 'up{job="api"}',
        "threshold": 1.0,
        "evaluator": "lt",
        "reducer": "last",
        "pending_for": "5m",
        "severity": "critical",
        "summary": "API is down",
        "description": "API health is {{ $values.B.Value }}.",
    }
    values.update(overrides)
    return AlertDefinition(**values)


def test_generated_uid_is_deterministic_and_valid() -> None:
    uid = generated_uid("A very long alert title " * 5)

    assert uid == generated_uid("A very long alert title " * 5)
    assert len(uid) <= 40
    assert uid.replace("-", "").isalnum()


def test_prometheus_selector_escapes_matcher_values() -> None:
    selector = prometheus_selector(
        "http_requests_total",
        [("job", "=", 'api\\primary"one'), ("status", "=~", "5..")],
    )

    assert selector == (
        'http_requests_total{job="api\\\\primary\\"one",status=~"5.."}'
    )


def test_alert_definition_rejects_unsupported_evaluator() -> None:
    with pytest.raises(ConfigError, match="evaluator"):
        _definition(evaluator="gte")


def test_write_site_with_alert_creates_renderable_copy(tmp_path: Path) -> None:
    output = tmp_path / "example-with-api-alert.yaml"

    written = write_site_with_alert(
        "sites/example.yaml", output, _definition(), "templates"
    )

    assert written == output.resolve()
    site = load_site(output)
    rendered = render_site(site, "templates")
    generated = rendered[-1].payload
    rule = generated["rules"][0]
    assert generated["title"] == "generated-api-down"
    assert rule["uid"] == "api-down"
    assert rule["data"][0]["model"]["expr"] == 'up{job="api"}'
    assert rule["data"][2]["model"]["conditions"][0]["evaluator"] == {
        "params": [1.0],
        "type": "lt",
    }
    assert rule["labels"]["severity"] == "critical"


def test_write_site_with_alert_preserves_source_and_refuses_overwrite(
    tmp_path: Path,
) -> None:
    source = tmp_path / "site.yaml"
    source.write_text(Path("sites/example.yaml").read_text(encoding="utf-8"), encoding="utf-8")
    original = source.read_text(encoding="utf-8")
    output = tmp_path / "generated.yaml"
    output.write_text("existing\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="already exists"):
        write_site_with_alert(source, output, _definition(), "templates")
    with pytest.raises(ConfigError, match="must differ"):
        write_site_with_alert(source, source, _definition(), "templates", overwrite=True)

    assert source.read_text(encoding="utf-8") == original
    assert output.read_text(encoding="utf-8") == "existing\n"


def test_write_site_with_alert_rejects_duplicate_group(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="Duplicate group name"):
        write_site_with_alert(
            "sites/example.yaml",
            tmp_path / "duplicate.yaml",
            _definition(group_name="host-health"),
            "templates",
        )


def test_create_alert_command_supports_fully_specified_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeClient:
        def list_datasources(self) -> list[dict[str, object]]:
            return [
                {
                    "name": "Prometheus",
                    "uid": "prometheus-main",
                    "type": "prometheus",
                }
            ]

        def query_prometheus(
            self, datasource_uid: str, expression: str
        ) -> dict[str, object]:
            assert datasource_uid == "prometheus-main"
            assert expression == 'up{job="api"}'
            return {"resultType": "vector", "result": [{"value": [1, "1"]}]}

    monkeypatch.setattr(cli, "_authenticated_client", lambda: FakeClient())
    output = tmp_path / "generated.yaml"
    result = runner.invoke(
        cli.app,
        [
            "create-alert",
            "sites/example.yaml",
            "--output",
            str(output),
            "--datasource",
            "prometheus-main",
            "--expr",
            'up{job="api"}',
            "--group",
            "generated-api-down",
            "--title",
            "API down",
            "--uid",
            "api-down",
            "--threshold",
            "1",
            "--evaluator",
            "lt",
            "--reducer",
            "last",
            "--pending-for",
            "5m",
            "--severity",
            "critical",
            "--summary",
            "API is down",
            "--description",
            "API health failed",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "PromQL valid: vector, 1 result(s)" in result.output
    assert output.is_file()
    raw = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert raw["groups"][-1]["template"] == "prometheus-alert.yaml.j2"
