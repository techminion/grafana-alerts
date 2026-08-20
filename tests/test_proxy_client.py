import pytest
import responses

from grafana_alerts.exceptions import ProxyApiError
from grafana_alerts.proxy_client import ProxyWriteClient


def _client() -> ProxyWriteClient:
    return ProxyWriteClient(
        "https://proxy.example/",
        "grafana-secret",
        "example",
        1,
        "folder/uid",
        "a" * 64,
        "attestation-secret-at-least-32-bytes",
        pipeline={"buildId": "41"},
    )


@responses.activate
def test_proxy_client_forwards_grafana_token_and_audit_result() -> None:
    responses.put(
        "https://proxy.example/v1/sites/example/groups/host%20health",
        json={
            "group": "host health",
            "statusCode": 202,
            "auditId": "request-1",
            "auditSha256": "b" * 64,
        },
        status=200,
    )

    result = _client().apply_group(
        "folder/uid", "host health", {"title": "host health"}
    )

    assert result.audit_id == "request-1"
    assert result.audit_sha256 == "b" * 64
    request = responses.calls[0].request
    assert request.headers["Authorization"] == "Bearer grafana-secret"
    body = request.body.decode() if isinstance(request.body, bytes) else request.body
    assert '"orgId": 1' in body
    assert "grafanaUrl" not in body
    assert "attestation-secret-at-least-32-bytes" not in body
    assert '"operation": "apply"' in body


@responses.activate
def test_proxy_client_uses_explicit_delete_action() -> None:
    responses.post(
        "https://proxy.example/v1/sites/example/groups/retired:delete",
        json={
            "group": "retired",
            "statusCode": 204,
            "auditId": "request-2",
            "auditSha256": "c" * 64,
        },
        status=200,
    )

    result = _client().delete_group("folder/uid", "retired", "d" * 64)

    assert result.status_code == 204
    assert responses.calls[0].request.method == "POST"


@responses.activate
def test_proxy_client_reports_server_rejection() -> None:
    responses.put(
        "https://proxy.example/v1/sites/example/groups/host-health",
        json={"detail": "Editor role cannot update rule groups"},
        status=403,
    )

    with pytest.raises(ProxyApiError, match="Editor role cannot update"):
        _client().apply_group("folder/uid", "host-health", {"title": "host-health"})


@responses.activate
def test_proxy_client_preserves_failed_mutation_audit_reference() -> None:
    responses.put(
        "https://proxy.example/v1/sites/example/groups/host-health",
        json={
            "detail": {
                "message": "Grafana rejected the rule group",
                "auditId": "request-failed",
                "auditSha256": "d" * 64,
            }
        },
        status=502,
    )

    with pytest.raises(ProxyApiError) as captured:
        _client().apply_group("folder/uid", "host-health", {"title": "host-health"})

    assert captured.value.audit_id == "request-failed"
    assert captured.value.audit_sha256 == "d" * 64


def test_proxy_client_rejects_folder_substitution() -> None:
    with pytest.raises(ProxyApiError, match="folder"):
        _client().delete_group("other-folder", "retired", "d" * 64)
