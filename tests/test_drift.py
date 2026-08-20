import copy
import json
from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

import grafana_alerts.cli as cli
from grafana_alerts.artifacts import write_bundle
from grafana_alerts.config import load_site
from grafana_alerts.drift import detect_drift, write_drift_report
from grafana_alerts.exceptions import GrafanaApiError
from grafana_alerts.renderer import render_site

runner = CliRunner()


class FakeClient:
    def __init__(self, groups, *, fail: set[str] | None = None) -> None:
        self.groups = groups
        self.fail = fail or set()
        self.requests: list[str] = []

    def get_group(self, folder_uid: str, group: str):
        assert folder_uid == "infrastructure-alerts"
        self.requests.append(group)
        if group in self.fail:
            raise GrafanaApiError("Grafana read failed")
        return self.groups.get(group)


def _inputs(tmp_path: Path, allowlist: list[str] | None = None):
    raw = Path("sites/example.yaml").read_text(encoding="utf-8")
    raw = raw.replace(
        "allow_groups: []", f"allow_groups: {json.dumps(allowlist or [])}"
    )
    site_path = tmp_path / "site.yaml"
    site_path.write_text(raw, encoding="utf-8")
    site = load_site(site_path)
    bundle = write_bundle(
        site, render_site(site, "templates"), tmp_path / "artifacts"
    )
    return site_path, site, bundle


def test_clean_report_checks_desired_and_allowlisted_absence(tmp_path: Path) -> None:
    _, site, bundle = _inputs(tmp_path, ["retired"])
    client = FakeClient({"host-health": bundle.groups[0].payload})

    report = detect_drift(site, bundle, "drift-reader", client)

    assert report.status == "clean"
    assert [(check.group, check.status) for check in report.checks] == [
        ("host-health", "in-sync"),
        ("retired", "absent"),
    ]
    assert report.payload()["summary"] == {
        "checked": 2,
        "in-sync": 1,
        "absent": 1,
        "missing": 0,
        "modified": 0,
        "unexpected": 0,
        "error": 0,
    }


def test_report_captures_modified_and_unexpected_groups_with_diff(
    tmp_path: Path,
) -> None:
    _, site, bundle = _inputs(tmp_path, ["retired"])
    modified = copy.deepcopy(bundle.groups[0].payload)
    modified["rules"][0]["for"] = "30m"
    client = FakeClient(
        {
            "host-health": modified,
            "retired": {"title": "retired", "rules": [{"uid": "legacy"}]},
        }
    )

    report = detect_drift(site, bundle, "drift-reader", client)
    path = write_drift_report(report, tmp_path / "report")

    assert report.status == "drift"
    assert [(check.group, check.status) for check in report.checks] == [
        ("host-health", "modified"),
        ("retired", "unexpected"),
    ]
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["identity"] == "drift-reader"
    assert payload["artifactManifestSha256"]
    assert payload["groups"][0]["desiredSha256"]
    assert payload["groups"][0]["liveSha256"]
    assert "30m" in (tmp_path / "report" / "host-health.diff").read_text()
    assert "token" not in path.read_text(encoding="utf-8").casefold()


def test_missing_and_read_errors_fail_closed(tmp_path: Path) -> None:
    _, site, bundle = _inputs(tmp_path, ["retired"])
    missing = detect_drift(site, bundle, "reader", FakeClient({}))
    error = detect_drift(
        site, bundle, "reader", FakeClient({}, fail={"host-health"})
    )

    assert missing.status == "drift"
    assert missing.checks[0].status == "missing"
    assert error.status == "error"
    assert error.checks[0].error == "Grafana read failed"


def test_drift_command_writes_report_and_exits_two_on_drift(
    tmp_path: Path, monkeypatch
) -> None:
    site_path, _, bundle = _inputs(tmp_path)
    client = FakeClient({})
    monkeypatch.setattr(
        cli,
        "_site_preflight",
        lambda site: (client, SimpleNamespace(identity="drift-reader")),
    )
    output = tmp_path / "cli-report"

    result = runner.invoke(
        cli.app,
        [
            "drift",
            str(site_path),
            "--artifact-dir",
            str(bundle.directory),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 2
    assert "Managed Grafana drift detected" in result.output
    assert json.loads((output / "drift-report.json").read_text())["status"] == "drift"
