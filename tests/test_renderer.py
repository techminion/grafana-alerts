from grafana_alerts.config import load_site
from grafana_alerts.renderer import render_site


def test_example_renders_valid_rule_group() -> None:
    site = load_site("sites/example.yaml")

    groups = render_site(site, "templates")

    assert len(groups) == 1
    group = groups[0].payload
    assert group["title"] == "host-health"
    assert group["folderUid"] == "infrastructure-alerts"
    assert len(group["rules"]) == 2
    assert group["rules"][0]["data"][2]["model"]["conditions"][0]["evaluator"][
        "params"
    ] == [85]
    assert group["rules"][0]["annotations"]["summary"] == (
        "High CPU usage on {{ $labels.instance }}"
    )


def test_rendering_is_deterministic() -> None:
    site = load_site("sites/example.yaml")

    first = render_site(site, "templates")
    second = render_site(site, "templates")

    assert first == second

