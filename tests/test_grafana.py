import pytest
import responses

from grafana_alerts.exceptions import GrafanaApiError
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


@responses.activate
def test_delete_group_uses_exact_encoded_endpoint() -> None:
    responses.delete(
        "https://grafana.example/api/v1/provisioning/folder/folder%2Fuid/rule-groups/old%20group",
        status=204,
    )

    result = GrafanaClient("https://grafana.example", "secret").delete_group(
        "folder/uid", "old group"
    )

    assert result.status_code == 204
    assert responses.calls[0].request.headers["Authorization"] == "Bearer secret"


@responses.activate
def test_list_datasources_uses_token() -> None:
    responses.get(
        "https://grafana.example/api/datasources",
        json=[{"name": "Prometheus", "uid": "prom-main", "type": "prometheus"}],
    )

    sources = GrafanaClient("https://grafana.example", "secret").list_datasources()

    assert sources[0]["uid"] == "prom-main"
    assert responses.calls[0].request.headers["Authorization"] == "Bearer secret"


@responses.activate
def test_prometheus_metrics_use_grafana_proxy() -> None:
    responses.get(
        "https://grafana.example/api/datasources/proxy/uid/prom%2Fmain/api/v1/label/__name__/values",
        json={"status": "success", "data": ["up", "http_requests_total"]},
    )

    metrics = GrafanaClient("https://grafana.example", "secret").prometheus_metrics(
        "prom/main"
    )

    assert metrics == ["up", "http_requests_total"]


@responses.activate
def test_prometheus_labels_can_be_scoped_to_metric() -> None:
    responses.get(
        "https://grafana.example/api/datasources/proxy/uid/prom/api/v1/labels",
        match=[responses.matchers.query_param_matcher({"match[]": "node_cpu_seconds_total"})],
        json={"status": "success", "data": ["cpu", "instance", "mode"]},
    )

    labels = GrafanaClient("https://grafana.example", "secret").prometheus_labels(
        "prom", metric="node_cpu_seconds_total"
    )

    assert labels == ["cpu", "instance", "mode"]


@responses.activate
def test_prometheus_label_values_encode_label_and_scope_metric() -> None:
    responses.get(
        "https://grafana.example/api/datasources/proxy/uid/prom/api/v1/label/job%2Fname/values",
        match=[responses.matchers.query_param_matcher({"match[]": "up"})],
        json={"status": "success", "data": ["api", "worker"]},
    )

    values = GrafanaClient("https://grafana.example", "secret").prometheus_label_values(
        "prom", "job/name", metric="up"
    )

    assert values == ["api", "worker"]


@responses.activate
def test_query_prometheus_passes_expression_and_time() -> None:
    responses.get(
        "https://grafana.example/api/datasources/proxy/uid/prom/api/v1/query",
        match=[
            responses.matchers.query_param_matcher(
                {"query": 'up{job="api"}', "time": "2026-08-18T04:00:00Z"}
            )
        ],
        json={
            "status": "success",
            "data": {"resultType": "vector", "result": []},
        },
    )

    result = GrafanaClient("https://grafana.example", "secret").query_prometheus(
        "prom", 'up{job="api"}', time="2026-08-18T04:00:00Z"
    )

    assert result == {"resultType": "vector", "result": []}


@responses.activate
def test_prometheus_error_response_is_rejected() -> None:
    responses.get(
        "https://grafana.example/api/datasources/proxy/uid/prom/api/v1/query",
        json={"status": "error", "errorType": "bad_data", "error": "invalid expression"},
    )

    with pytest.raises(GrafanaApiError, match="invalid expression"):
        GrafanaClient("https://grafana.example", "secret").query_prometheus("prom", "bad(")


def test_invalid_metric_name_is_rejected_before_request() -> None:
    with pytest.raises(GrafanaApiError, match="Invalid Prometheus metric name"):
        GrafanaClient("https://grafana.example", "secret").prometheus_labels(
            "prom", metric='up{job="api"}'
        )
