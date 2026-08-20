import copy
import json
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient

from grafana_alerts.attestation import create_mutation_attestation
from grafana_alerts.config import load_site
from grafana_alerts.deployment_plan import live_group_sha256
from grafana_alerts.exceptions import ConfigError
from grafana_alerts.proxy_app import ProxySettings, create_app
from grafana_alerts.renderer import render_site

ATTESTATION_KEY = "test-attestation-secret-at-least-32-bytes"


class FakeGrafana:
    def __init__(self, login: str = "deployer") -> None:
        self.login = login
        self.groups: dict[str, dict[str, object]] = {}
        self.applied: list[str] = []
        self.deleted: list[str] = []

    def whoami(self):
        return {"id": 17, "login": self.login, "email": "trusted@example.test"}

    def current_org(self):
        return {"id": 1, "name": "Main Org"}

    def get_group(self, folder_uid: str, group: str):
        return self.groups.get(group)

    def apply_group(self, folder_uid: str, group: str, payload: dict[str, object]):
        self.groups[group] = payload
        self.applied.append(group)
        return SimpleNamespace(group=group, status_code=202)

    def delete_group(self, folder_uid: str, group: str):
        self.groups.pop(group)
        self.deleted.append(group)
        return SimpleNamespace(group=group, status_code=204)


def _payload() -> dict[str, object]:
    site = load_site("sites/example.yaml")
    return render_site(site, "templates")[0].payload


def _request(
    payload: dict[str, object] | None = None,
    *,
    operation: str = "apply",
    before: dict[str, object] | None = None,
    org_id: int = 1,
) -> dict[str, object]:
    request: dict[str, object] = {
        "orgId": org_id,
        "folderUid": "infrastructure-alerts",
        "artifactManifestSha256": "a" * 64,
        "pipeline": {"buildId": "41"},
    }
    if payload is not None:
        request["payload"] = payload
    request["attestation"] = create_mutation_attestation(
        ATTESTATION_KEY,
        site="example",
        org_id=org_id,
        folder_uid="infrastructure-alerts",
        group="host-health",
        operation=operation,
        artifact_manifest_sha256="a" * 64,
        payload_sha256=live_group_sha256(payload) if payload is not None else None,
        expected_before_sha256=(
            live_group_sha256(before) if before is not None else None
        ),
    )
    return request


def _client(
    tmp_path: Path, role: str, fake: FakeGrafana | None = None
) -> tuple[TestClient, FakeGrafana]:
    grafana = fake or FakeGrafana()
    tmp_path.mkdir(parents=True, exist_ok=True)
    rbac = tmp_path / "rbac.yaml"
    rbac.write_text(
        "\n".join(
            [
                "schemaVersion: 1",
                "identities:",
                "  - match:",
                f"      login: {grafana.login}",
                f"    role: {role}",
                "    sites: [example]",
                "",
            ]
        ),
        encoding="utf-8",
    )
    settings = ProxySettings(
        grafana_url="https://grafana.example",
        sites_dir=Path("sites"),
        rbac_file=rbac,
        audit_dir=tmp_path / "audit",
        attestation_key=ATTESTATION_KEY,
    )
    app = create_app(settings, client_factory=lambda url, token: grafana)
    return TestClient(app), grafana


def test_editor_can_create_and_proxy_writes_before_outcome_audit(tmp_path: Path) -> None:
    client, grafana = _client(tmp_path, "Editor")
    request = _request(_payload())

    response = client.put(
        "/v1/sites/example/groups/host-health",
        headers={"Authorization": "Bearer grafana-token"},
        json=request,
    )

    assert response.status_code == 200, response.text
    assert grafana.applied == ["host-health"]
    body = response.json()
    assert body["auditSha256"]
    assert body["auditId"] == request["attestation"]["statement"]["nonce"]
    records = sorted((tmp_path / "audit").glob("*.json"))
    assert [path.name.split(".")[-2] for path in records] == ["intent", "outcome"]
    intent = json.loads(records[0].read_text(encoding="utf-8"))
    outcome = json.loads(records[1].read_text(encoding="utf-8"))
    assert intent["before"] is None
    assert intent["after"]["title"] == "host-health"
    assert len(intent["attestationSha256"]) == 64
    assert outcome["status"] == "succeeded"
    assert "grafana-token" not in json.dumps([intent, outcome])
    assert ATTESTATION_KEY not in json.dumps([intent, outcome])


def test_editor_cannot_update_and_viewer_cannot_create(tmp_path: Path) -> None:
    payload = _payload()
    editor_fake = FakeGrafana()
    editor_fake.groups["host-health"] = payload
    editor, _ = _client(tmp_path / "editor", "Editor", editor_fake)

    update = editor.put(
        "/v1/sites/example/groups/host-health",
        headers={"Authorization": "Bearer token"},
        json=_request(payload),
    )
    assert update.status_code == 403
    assert "cannot update" in update.json()["detail"]

    viewer, viewer_fake = _client(tmp_path / "viewer", "Viewer")
    create = viewer.put(
        "/v1/sites/example/groups/host-health",
        headers={"Authorization": "Bearer token"},
        json=_request(payload),
    )
    assert create.status_code == 403
    assert viewer_fake.applied == []


def test_admin_can_update_and_delete(tmp_path: Path) -> None:
    payload = _payload()
    fake = FakeGrafana()
    fake.groups["host-health"] = payload
    client, _ = _client(tmp_path, "Admin", fake)

    update = client.put(
        "/v1/sites/example/groups/host-health",
        headers={"Authorization": "Bearer token"},
        json=_request(payload),
    )
    delete = client.post(
        "/v1/sites/example/groups/host-health:delete",
        headers={"Authorization": "Bearer token"},
        json=_request(operation="delete", before=payload),
    )

    assert update.status_code == 200, update.text
    assert delete.status_code == 200, delete.text
    assert fake.applied == ["host-health"]
    assert fake.deleted == ["host-health"]


def test_client_cannot_supply_identity_or_change_site_target(tmp_path: Path) -> None:
    client, grafana = _client(tmp_path, "Admin")
    request = _request(_payload())
    request["identity"] = {"login": "deployment-admin"}

    identity = client.put(
        "/v1/sites/example/groups/host-health",
        headers={"Authorization": "Bearer token"},
        json=request,
    )
    wrong_org = _request(_payload(), org_id=2)
    target = client.put(
        "/v1/sites/example/groups/host-health",
        headers={"Authorization": "Bearer token"},
        json=wrong_org,
    )

    assert identity.status_code == 422
    assert target.status_code == 409
    assert grafana.applied == []


def test_failed_intent_audit_prevents_mutation(tmp_path: Path) -> None:
    fake = FakeGrafana()
    rbac = tmp_path / "rbac.yaml"
    rbac.write_text(
        "schemaVersion: 1\nidentities:\n  - match: {login: deployer}\n"
        "    role: Admin\n    sites: [example]\n",
        encoding="utf-8",
    )
    settings = ProxySettings(
        "https://grafana.example",
        Path("sites"),
        rbac,
        tmp_path / "audit",
        ATTESTATION_KEY,
    )

    def fail_audit(*args, **kwargs):
        raise ConfigError("audit storage unavailable")

    client = TestClient(
        create_app(
            settings,
            client_factory=lambda url, token: fake,
            audit_writer=fail_audit,
        )
    )
    response = client.put(
        "/v1/sites/example/groups/host-health",
        headers={"Authorization": "Bearer token"},
        json=_request(_payload()),
    )

    assert response.status_code == 500
    assert fake.applied == []


def test_bearer_token_is_required(tmp_path: Path) -> None:
    client, _ = _client(tmp_path, "Admin")

    response = client.put(
        "/v1/sites/example/groups/host-health", json=_request(_payload())
    )

    assert response.status_code == 401


def test_tampered_payload_is_rejected_before_grafana_mutation(tmp_path: Path) -> None:
    client, grafana = _client(tmp_path, "Admin")
    payload = _payload()
    request = _request(payload)
    tampered = copy.deepcopy(payload)
    tampered["rules"][0]["for"] = "30m"
    request["payload"] = tampered

    response = client.put(
        "/v1/sites/example/groups/host-health",
        headers={"Authorization": "Bearer token"},
        json=request,
    )

    assert response.status_code == 403
    assert "attestation" in response.json()["detail"].casefold()
    assert grafana.applied == []


def test_attestation_nonce_cannot_be_replayed(tmp_path: Path) -> None:
    client, grafana = _client(tmp_path, "Admin")
    request = _request(_payload())

    first = client.put(
        "/v1/sites/example/groups/host-health",
        headers={"Authorization": "Bearer token"},
        json=request,
    )
    replay = client.put(
        "/v1/sites/example/groups/host-health",
        headers={"Authorization": "Bearer token"},
        json=request,
    )

    assert first.status_code == 200
    assert replay.status_code == 409
    assert grafana.applied == ["host-health"]


def test_delete_attestation_rejects_changed_before_state(tmp_path: Path) -> None:
    reviewed = _payload()
    current = copy.deepcopy(reviewed)
    current["rules"][0]["for"] = "30m"
    fake = FakeGrafana()
    fake.groups["host-health"] = current
    client, _ = _client(tmp_path, "Admin", fake)

    response = client.post(
        "/v1/sites/example/groups/host-health:delete",
        headers={"Authorization": "Bearer token"},
        json=_request(operation="delete", before=reviewed),
    )

    assert response.status_code == 403
    assert "expectedBeforeSha256" in response.json()["detail"]
    assert fake.deleted == []
