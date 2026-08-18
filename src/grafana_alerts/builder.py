from __future__ import annotations

import hashlib
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from grafana_alerts.config import load_site
from grafana_alerts.exceptions import ConfigError
from grafana_alerts.renderer import render_site

_METRIC_PATTERN = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$")
_LABEL_PATTERN = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
_UID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
_DURATION_PATTERN = re.compile(r"^(0|[1-9][0-9]*)(ms|s|m|h|d|w)$")
_MATCHER_OPERATORS = {"=", "!=", "=~", "!~"}
_EVALUATORS = {"gt", "lt"}
_REDUCERS = {"last", "avg", "min", "max", "sum"}
_STATES = {"Alerting", "Error", "KeepLast", "NoData", "Normal", "OK"}


@dataclass(frozen=True)
class AlertDefinition:
    group_name: str
    uid: str
    title: str
    datasource_uid: str
    expression: str
    threshold: float
    evaluator: str
    reducer: str
    pending_for: str
    severity: str
    summary: str
    description: str
    evaluation_interval_seconds: int = 60
    query_window_seconds: int = 600
    no_data_state: str = "NoData"
    exec_error_state: str = "Error"

    def __post_init__(self) -> None:
        required = {
            "group_name": self.group_name,
            "title": self.title,
            "datasource_uid": self.datasource_uid,
            "expression": self.expression,
            "severity": self.severity,
            "summary": self.summary,
            "description": self.description,
        }
        empty = [name for name, value in required.items() if not value.strip()]
        if empty:
            raise ConfigError(f"Alert fields cannot be empty: {', '.join(empty)}")
        if not _UID_PATTERN.fullmatch(self.uid):
            raise ConfigError(
                "Alert UID must be 1-40 characters using letters, numbers, '-' or '_'"
            )
        if self.evaluator not in _EVALUATORS:
            raise ConfigError("Alert evaluator must be gt or lt")
        if self.reducer not in _REDUCERS:
            raise ConfigError(
                f"Alert reducer must be one of: {', '.join(sorted(_REDUCERS))}"
            )
        if not _DURATION_PATTERN.fullmatch(self.pending_for):
            raise ConfigError("Alert pending_for must be a Grafana duration such as 0s, 5m or 1h")
        if self.evaluation_interval_seconds <= 0 or self.query_window_seconds <= 0:
            raise ConfigError("Alert evaluation interval and query window must be positive")
        for field_name, state in (
            ("no_data_state", self.no_data_state),
            ("exec_error_state", self.exec_error_state),
        ):
            if state not in _STATES:
                raise ConfigError(f"Alert {field_name} has unsupported state {state!r}")

    def site_group(self) -> dict[str, Any]:
        return {
            "name": self.group_name,
            "template": "prometheus-alert.yaml.j2",
            "uid": self.uid,
            "title": self.title,
            "datasource_uid": self.datasource_uid,
            "query": self.expression,
            "threshold": self.threshold,
            "evaluator": self.evaluator,
            "reducer": self.reducer,
            "pending_for": self.pending_for,
            "severity": self.severity,
            "summary": self.summary,
            "description": self.description,
            "evaluation_interval_seconds": self.evaluation_interval_seconds,
            "query_window_seconds": self.query_window_seconds,
            "no_data_state": self.no_data_state,
            "exec_error_state": self.exec_error_state,
        }


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")
    return slug or "alert"


def generated_uid(title: str) -> str:
    digest = hashlib.sha256(title.encode("utf-8")).hexdigest()[:8]
    return f"{slugify(title)[:31]}-{digest}"


def prometheus_selector(
    metric: str,
    matchers: list[tuple[str, str, str]],
) -> str:
    if not _METRIC_PATTERN.fullmatch(metric):
        raise ConfigError(f"Invalid Prometheus metric name: {metric}")
    rendered: list[str] = []
    for label, operator, value in matchers:
        if not _LABEL_PATTERN.fullmatch(label):
            raise ConfigError(f"Invalid Prometheus label name: {label}")
        if operator not in _MATCHER_OPERATORS:
            raise ConfigError(f"Invalid Prometheus label matcher operator: {operator}")
        escaped = value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')
        rendered.append(f'{label}{operator}"{escaped}"')
    return f"{metric}{{{','.join(rendered)}}}" if rendered else metric


def write_site_with_alert(
    site_file: str | Path,
    output_file: str | Path,
    definition: AlertDefinition,
    template_dir: str | Path,
    *,
    overwrite: bool = False,
) -> Path:
    source = Path(site_file).resolve()
    output = Path(output_file).resolve()
    if source == output:
        raise ConfigError("Alert builder output must differ from the source site file")
    if output.exists() and not overwrite:
        raise ConfigError(f"Alert builder output already exists: {output}")

    try:
        raw = yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"Unable to read site config {source}: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("groups"), list):
        raise ConfigError(f"Site config has no groups list: {source}")

    existing_names = {
        item.get("name") for item in raw["groups"] if isinstance(item, dict)
    }
    if definition.group_name in existing_names:
        raise ConfigError(f"Duplicate group name: {definition.group_name}")
    raw["groups"].append(definition.site_group())

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            yaml.safe_dump(raw, temporary, sort_keys=False, allow_unicode=True)
            temporary_path = Path(temporary.name)

        generated_site = load_site(temporary_path)
        render_site(generated_site, template_dir)
        os.replace(temporary_path, output)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return output
