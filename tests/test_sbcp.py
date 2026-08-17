from grafana_alerts.config import load_site
from grafana_alerts.renderer import render_site


def test_sbcp_export_renders_all_rules() -> None:
    site = load_site("sites/sbcp.yaml")

    groups = render_site(site, "templates")
    rules = [rule for group in groups for rule in group.payload["rules"]]

    assert len(groups) == 28
    assert len(rules) == 676
    assert {group.payload["interval"] for group in groups} == {60}
    assert {rule["orgId"] for rule in rules} == {10}
    assert {rule["folderUID"] for rule in rules} == {"cfq41jl2svbi8a"}


def test_sbcp_site_and_datasource_markers_are_resolved() -> None:
    site = load_site("sites/sbcp.yaml")

    groups = render_site(site, "templates")
    rules = [rule for group in groups for rule in group.payload["rules"]]
    serialized = str([group.payload for group in groups])
    datasource_uids = {
        query["datasourceUid"]
        for rule in rules
        for query in rule["data"]
    }

    assert "__SITE_NAME__" not in serialized
    assert "__ENVIRONMENT__" not in serialized
    assert "[SBCP][PROD]" in serialized
    assert {"afq2sc9yp1u68f", "ffq2s7k65isxse"} <= datasource_uids


def test_sbcp_first_rule_is_preserved() -> None:
    site = load_site("sites/sbcp.yaml")

    first_group = render_site(site, "templates")[0].payload
    first_rule = first_group["rules"][0]

    assert first_group["title"] == "Fluent-Bit-Alerts"
    assert first_rule["uid"] == "afd3j2l6om1a8d"
    assert first_rule["title"] == "[SBCP][PROD] Node-Fluent-Bit-Down"
    assert first_rule["for"] == "5m"
    assert 'site_name="SBCP"' in first_rule["data"][0]["model"]["expr"]
