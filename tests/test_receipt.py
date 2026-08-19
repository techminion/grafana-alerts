import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import grafana_alerts.cli as cli
from grafana_alerts.exceptions import ConfigError
from grafana_alerts.receipt import (
    ReceiptRecorder,
    load_and_verify_receipt,
    pipeline_metadata,
    receipt_sidecar,
    write_receipt,
)

runner = CliRunner()


def _recorder() -> ReceiptRecorder:
    recorder = ReceiptRecorder(
        started_at="2026-08-19T10:00:00Z",
        pipeline={"buildId": "42", "sourceVersion": "abc123"},
    )
    recorder.target("sbcp", 1, "infrastructure-alerts")
    recorder.identity = "alert-deployer"
    recorder.artifact_manifest_sha256 = "a" * 64
    recorder.deployment_plan_sha256 = "b" * 64
    recorder.record("host-health", "apply", "succeeded", http_status=202)
    return recorder


def test_receipt_round_trip_preserves_audit_fields(tmp_path: Path) -> None:
    path = tmp_path / "deployment-receipt.json"
    payload = _recorder().payload(
        "succeeded", finished_at="2026-08-19T10:01:00Z"
    )

    digest = write_receipt(path, payload)
    verified = load_and_verify_receipt(path)

    assert verified == payload
    assert verified["identity"] == "alert-deployer"
    assert verified["operations"][0]["httpStatus"] == 202
    assert receipt_sidecar(path).read_text(encoding="utf-8").startswith(digest)


def test_receipt_refuses_to_overwrite_existing_record(tmp_path: Path) -> None:
    path = tmp_path / "deployment-receipt.json"
    payload = _recorder().payload("succeeded")
    write_receipt(path, payload)

    with pytest.raises(ConfigError, match="already exists"):
        write_receipt(path, payload)


def test_receipt_detects_tampering(tmp_path: Path) -> None:
    path = tmp_path / "deployment-receipt.json"
    write_receipt(path, _recorder().payload("succeeded"))
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["identity"] = "someone-else"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ConfigError, match="integrity check failed"):
        load_and_verify_receipt(path)


def test_failed_receipt_requires_an_error() -> None:
    with pytest.raises(ConfigError, match="must include an error"):
        write_receipt(
            Path("unused.json"),
            _recorder().payload("failed", finished_at="2026-08-19T10:01:00Z"),
        )


def test_pipeline_metadata_uses_only_named_non_secret_fields() -> None:
    metadata = pipeline_metadata(
        {
            "BUILD_BUILDID": "42",
            "BUILD_SOURCEVERSION": "abc123",
            "GRAFANA_TOKEN": "secret",
        }
    )

    assert metadata == {"buildId": "42", "sourceVersion": "abc123"}


def test_verify_receipt_command_reports_valid_receipt(tmp_path: Path) -> None:
    path = tmp_path / "deployment-receipt.json"
    write_receipt(path, _recorder().payload("succeeded"))

    result = runner.invoke(cli.app, ["verify-receipt", str(path)])

    assert result.exit_code == 0, result.output
    assert "Valid succeeded deployment receipt" in result.output


def test_receipt_validates_linked_rollback_metadata(tmp_path: Path) -> None:
    path = tmp_path / "rollback-receipt.json"
    recorder = _recorder()
    recorder.link_rollback("Revert regression", "c" * 64, "d" * 64)

    write_receipt(path, recorder.payload("succeeded"))
    payload = load_and_verify_receipt(path)

    assert payload["rollback"] == {
        "reason": "Revert regression",
        "sourceReceiptSha256": "c" * 64,
        "planSha256": "d" * 64,
    }


def test_receipt_validates_post_deployment_verification(tmp_path: Path) -> None:
    path = tmp_path / "verified-receipt.json"
    recorder = _recorder()
    recorder.record_verification(
        {
            "status": "succeeded",
            "groups": [
                {
                    "group": "host-health",
                    "targetState": "present",
                    "status": "succeeded",
                    "attempts": 1,
                    "desiredSha256": "e" * 64,
                    "liveSha256": "e" * 64,
                }
            ],
            "queries": [
                {
                    "datasourceUid": "prometheus-main",
                    "expressionSha256": "f" * 64,
                    "references": ["host-health/rule:A"],
                    "status": "succeeded",
                    "attempts": 1,
                    "resultType": "vector",
                    "resultCount": 0,
                }
            ],
        }
    )

    write_receipt(path, recorder.payload("succeeded"))
    payload = load_and_verify_receipt(path)

    assert payload["verification"]["status"] == "succeeded"


def test_receipt_rejects_inconsistent_verification_status() -> None:
    recorder = _recorder()
    recorder.record_verification(
        {
            "status": "failed",
            "groups": [
                {
                    "group": "host-health",
                    "targetState": "present",
                    "status": "succeeded",
                    "attempts": 1,
                }
            ],
            "queries": [],
        }
    )

    with pytest.raises(ConfigError, match="status is inconsistent"):
        write_receipt(Path("unused.json"), recorder.payload("failed", "failed"))
