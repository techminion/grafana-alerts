from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from grafana_alerts.exceptions import ConfigError


@dataclass(frozen=True)
class AuditRecord:
    audit_id: str
    sha256: str
    path: Path


def write_audit_record(
    audit_dir: str | Path,
    audit_id: str,
    phase: str,
    payload: dict[str, Any],
) -> AuditRecord:
    """Exclusively create one immutable audit record and its fingerprint sidecar."""
    if phase not in {"intent", "outcome"}:
        raise ConfigError(f"Unsupported proxy audit phase: {phase}")
    directory = Path(audit_dir)
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ConfigError(f"Unable to prepare proxy audit directory: {exc}") from exc

    record_path = directory / f"{audit_id}.{phase}.json"
    sidecar_path = record_path.with_name(f"{record_path.name}.sha256")
    content = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    fingerprint = hashlib.sha256(content).hexdigest()
    try:
        with record_path.open("xb") as stream:
            stream.write(content)
        with sidecar_path.open("x", encoding="utf-8") as stream:
            stream.write(f"{fingerprint}  {record_path.name}\n")
    except FileExistsError as exc:
        raise ConfigError(f"Proxy audit record already exists: {exc.filename}") from exc
    except OSError as exc:
        raise ConfigError(f"Unable to write proxy audit record: {exc}") from exc
    return AuditRecord(audit_id=audit_id, sha256=fingerprint, path=record_path)
