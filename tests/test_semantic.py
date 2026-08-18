import copy

from grafana_alerts.config import load_site
from grafana_alerts.renderer import render_site
from grafana_alerts.semantic import compare_group


def _desired_group():
    site = load_site("sites/example.yaml")
    return render_site(site, "templates")[0].payload


def test_semantic_comparison_ignores_order_and_volatile_fields() -> None:
    desired = _desired_group()
    current = copy.deepcopy(desired)
    current["rules"].reverse()
    for rule in current["rules"]:
        rule["id"] = 123
        rule["updated"] = "2026-08-17T00:00:00Z"
        rule["provenance"] = "api"
        rule["data"].reverse()
        for query in rule["data"]:
            if query["datasourceUid"] == "__expr__":
                query["datasourceUid"] = "-100"

    comparison = compare_group("host-health", desired, current)

    assert comparison.action == "no-change"
    assert comparison.diff == ""


def test_semantic_comparison_reports_update_diff() -> None:
    desired = _desired_group()
    current = copy.deepcopy(desired)
    current["rules"][0]["for"] = "30m"

    comparison = compare_group("host-health", desired, current)

    assert comparison.action == "update"
    assert "live/host-health.json" in comparison.diff
    assert '"for": "30m"' in comparison.diff
    assert '"for": "10m"' in comparison.diff


def test_semantic_comparison_reports_create() -> None:
    comparison = compare_group("host-health", _desired_group(), None)

    assert comparison.action == "create"
    assert comparison.diff == ""

