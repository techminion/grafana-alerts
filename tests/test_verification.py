import copy
from pathlib import Path

from grafana_alerts.artifacts import write_bundle
from grafana_alerts.config import load_site
from grafana_alerts.exceptions import GrafanaApiError
from grafana_alerts.renderer import render_site
from grafana_alerts.verification import verify_deployment


def _bundle(tmp_path: Path):
    site = load_site("sites/example.yaml")
    return write_bundle(site, render_site(site, "templates"), tmp_path / "artifacts")


class FakeVerificationClient:
    def __init__(self, groups: dict[str, dict[str, object] | None]) -> None:
        self.groups = groups
        self.query_calls: list[tuple[str, str]] = []
        self.group_calls: dict[str, int] = {}
        self.fail_queries = False

    def get_group(self, folder_uid: str, group: str) -> dict[str, object] | None:
        self.group_calls[group] = self.group_calls.get(group, 0) + 1
        return self.groups.get(group)

    def query_prometheus(
        self, datasource_uid: str, expression: str, *, time: str | None = None
    ) -> dict[str, object]:
        self.query_calls.append((datasource_uid, expression))
        if self.fail_queries:
            raise GrafanaApiError("Prometheus query failed")
        return {"resultType": "vector", "result": []}


def test_verification_accepts_semantic_match_and_empty_query_results(
    tmp_path: Path,
) -> None:
    bundle = _bundle(tmp_path)
    desired = copy.deepcopy(bundle.groups[0].payload)
    first_expression = desired["rules"][0]["data"][0]["model"]["expr"]
    desired["rules"][1]["data"][0]["model"]["expr"] = first_expression
    bundle.groups[0].payload["rules"][1]["data"][0]["model"]["expr"] = first_expression
    client = FakeVerificationClient({"host-health": desired})

    report = verify_deployment(
        bundle,
        "infrastructure-alerts",
        {"prometheus-main": "prometheus"},
        client,
        attempts=1,
        delay_seconds=0,
    )

    assert report.status == "succeeded"
    assert len(report.queries) == 1
    assert len(report.queries[0].references) == 2
    assert report.queries[0].result_count == 0
    assert len(client.query_calls) == 1


def test_verification_retries_eventually_consistent_group(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path)
    desired = bundle.groups[0].payload

    class EventuallyConsistentClient(FakeVerificationClient):
        def get_group(self, folder_uid: str, group: str) -> dict[str, object] | None:
            calls = self.group_calls.get(group, 0) + 1
            self.group_calls[group] = calls
            if calls == 1:
                changed = copy.deepcopy(desired)
                changed["rules"][0]["for"] = "30m"
                return changed
            return desired

    client = EventuallyConsistentClient({})

    report = verify_deployment(
        bundle,
        "infrastructure-alerts",
        {"prometheus-main": "prometheus"},
        client,
        attempts=2,
        delay_seconds=0,
    )

    assert report.status == "succeeded"
    assert report.groups[0].attempts == 2


def test_verification_reports_group_query_and_absence_failures(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path)
    changed = copy.deepcopy(bundle.groups[0].payload)
    changed["rules"][0]["for"] = "30m"
    client = FakeVerificationClient(
        {"host-health": changed, "retired": {"title": "retired", "rules": []}}
    )
    client.fail_queries = True

    report = verify_deployment(
        bundle,
        "infrastructure-alerts",
        {"prometheus-main": "prometheus"},
        client,
        expected_absent=["retired"],
        attempts=1,
        delay_seconds=0,
    )

    assert report.status == "failed"
    assert [(check.group, check.error) for check in report.groups] == [
        ("host-health", "semantic mismatch"),
        ("retired", "group still exists"),
    ]
    assert all(check.status == "failed" for check in report.queries)
    payload = report.payload()
    assert payload["groups"][0]["desiredSha256"]
    assert payload["queries"][0]["expressionSha256"]
    assert "expr" not in payload["queries"][0]
