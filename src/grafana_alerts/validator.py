from __future__ import annotations

import re
from typing import Any

from grafana_alerts.exceptions import ConfigError

_UID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
_DURATION_PATTERN = re.compile(r"^(0|[1-9][0-9]*)(ms|s|m|h|d|w)$")
_STATES = {"Alerting", "Error", "KeepLast", "NoData", "Normal", "OK"}


def _require(mapping: dict[str, Any], keys: tuple[str, ...], location: str) -> None:
    missing = [key for key in keys if key not in mapping]
    if missing:
        raise ConfigError(f"{location} is missing: {', '.join(missing)}")


def validate_group(group: dict[str, Any]) -> None:
    _require(group, ("title", "folderUid", "interval", "rules"), "rule group")

    if not isinstance(group["interval"], int) or group["interval"] <= 0:
        raise ConfigError("rule group interval must be a positive integer in seconds")
    if not isinstance(group["rules"], list) or not group["rules"]:
        raise ConfigError("rule group rules must be a non-empty list")

    seen_uids: set[str] = set()
    for index, rule in enumerate(group["rules"]):
        location = f"rules[{index}]"
        if not isinstance(rule, dict):
            raise ConfigError(f"{location} must be a mapping")
        _require(
            rule,
            (
                "uid",
                "title",
                "ruleGroup",
                "folderUID",
                "orgId",
                "condition",
                "data",
                "noDataState",
                "execErrState",
                "for",
            ),
            location,
        )
        uid = rule["uid"]
        if not isinstance(uid, str) or not _UID_PATTERN.fullmatch(uid):
            raise ConfigError(
                f"{location}.uid must be 1-40 characters using letters, numbers, '-' or '_'"
            )
        if uid in seen_uids:
            raise ConfigError(f"Duplicate rule UID: {uid}")
        seen_uids.add(uid)

        for state_key in ("noDataState", "execErrState"):
            if rule[state_key] not in _STATES:
                raise ConfigError(
                    f"{location}.{state_key} has unsupported state {rule[state_key]!r}"
                )
        if not isinstance(rule["for"], str) or not _DURATION_PATTERN.fullmatch(rule["for"]):
            raise ConfigError(f"{location}.for must be a Grafana duration such as 0s, 5m or 1h")
        if not isinstance(rule["data"], list) or not rule["data"]:
            raise ConfigError(f"{location}.data must be a non-empty list")

        ref_ids = {query.get("refId") for query in rule["data"] if isinstance(query, dict)}
        if rule["condition"] not in ref_ids:
            raise ConfigError(
                f"{location}.condition {rule['condition']!r} does not match a data refId"
            )
