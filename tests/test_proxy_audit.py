import hashlib
import json
from pathlib import Path

import pytest

from grafana_alerts.exceptions import ConfigError
from grafana_alerts.proxy_audit import write_audit_record


def test_audit_records_are_exclusive_and_fingerprinted(tmp_path: Path) -> None:
    payload = {"identity": {"login": "deployer"}, "before": None, "after": {"x": 1}}

    record = write_audit_record(tmp_path, "request-1", "intent", payload)

    content = record.path.read_bytes()
    assert record.sha256 == hashlib.sha256(content).hexdigest()
    assert json.loads(content)["after"] == {"x": 1}
    assert (tmp_path / "request-1.intent.json.sha256").read_text().startswith(
        record.sha256
    )
    with pytest.raises(ConfigError, match="already exists"):
        write_audit_record(tmp_path, "request-1", "intent", payload)


def test_audit_payload_does_not_gain_credentials(tmp_path: Path) -> None:
    record = write_audit_record(
        tmp_path,
        "request-2",
        "outcome",
        {"identity": {"login": "deployer"}, "status": "succeeded"},
    )

    assert "token" not in record.path.read_text(encoding="utf-8").casefold()
