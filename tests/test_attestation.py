import copy
from datetime import datetime, timedelta, timezone

import pytest

from grafana_alerts.attestation import (
    create_mutation_attestation,
    verify_mutation_attestation,
)
from grafana_alerts.exceptions import ConfigError

NOW = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
KEY = "shared-secret-with-at-least-32-bytes"


def _attestation(operation: str = "apply"):
    return create_mutation_attestation(
        KEY,
        site="example",
        org_id=1,
        folder_uid="alerts",
        group="host-health",
        operation=operation,
        artifact_manifest_sha256="a" * 64,
        payload_sha256="b" * 64 if operation == "apply" else None,
        expected_before_sha256="c" * 64 if operation == "delete" else None,
        now=NOW,
        nonce="1" * 32,
    )


def _expected(operation: str = "apply"):
    return {
        "site": "example",
        "orgId": 1,
        "folderUid": "alerts",
        "group": "host-health",
        "operation": operation,
        "artifactManifestSha256": "a" * 64,
        "payloadSha256": "b" * 64 if operation == "apply" else None,
        "expectedBeforeSha256": "c" * 64 if operation == "delete" else None,
    }


def test_attestation_binds_exact_mutation_and_validity_window() -> None:
    statement = verify_mutation_attestation(
        _attestation(), KEY, expected=_expected(), now=NOW
    )

    assert statement["nonce"] == "1" * 32
    assert statement["payloadSha256"] == "b" * 64


def test_attestation_rejects_tampering_wrong_key_and_expiry() -> None:
    tampered = copy.deepcopy(_attestation())
    tampered["statement"]["group"] = "another-group"

    with pytest.raises(ConfigError, match="signature verification failed"):
        verify_mutation_attestation(
            tampered, KEY, expected=_expected(), now=NOW
        )
    with pytest.raises(ConfigError, match="signature verification failed"):
        verify_mutation_attestation(
            _attestation(),
            "wrong-secret-with-at-least-32-bytes",
            expected=_expected(),
            now=NOW,
        )
    with pytest.raises(ConfigError, match="expired"):
        verify_mutation_attestation(
            _attestation(),
            KEY,
            expected=_expected(),
            now=NOW + timedelta(hours=1),
        )


def test_delete_attestation_requires_reviewed_before_state() -> None:
    statement = verify_mutation_attestation(
        _attestation("delete"),
        KEY,
        expected=_expected("delete"),
        now=NOW,
    )

    assert statement["payloadSha256"] is None
    assert statement["expectedBeforeSha256"] == "c" * 64
