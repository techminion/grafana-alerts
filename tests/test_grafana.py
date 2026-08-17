import responses

from grafana_alerts.grafana import GrafanaClient


@responses.activate
def test_apply_group_uses_encoded_group_endpoint() -> None:
    responses.put(
        "https://grafana.example/api/v1/provisioning/folder/folder%2Fuid/rule-groups/host%20health",
        json={"message": "ok"},
        status=202,
    )
    client = GrafanaClient("https://grafana.example/", "secret")

    result = client.apply_group("folder/uid", "host health", {"title": "host health"})

    assert result.status_code == 202
    request = responses.calls[0].request
    assert request.headers["Authorization"] == "Bearer secret"


@responses.activate
def test_get_group_returns_none_for_404() -> None:
    responses.get(
        "https://grafana.example/api/v1/provisioning/folder/alerts/rule-groups/missing",
        json={"message": "not found"},
        status=404,
    )
    client = GrafanaClient("https://grafana.example", "secret")

    assert client.get_group("alerts", "missing") is None

