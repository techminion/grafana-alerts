from __future__ import annotations

import difflib
import json
from dataclasses import dataclass
from typing import Any

VOLATILE_KEYS = {"id", "provenance", "updated", "version"}
KEY_ALIASES = {"orgID": "orgId"}


@dataclass(frozen=True)
class Comparison:
    group: str
    action: str
    diff: str


def canonicalize(value: Any, *, parent_key: str | None = None) -> Any:
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            key = KEY_ALIASES.get(key, key)
            if key in VOLATILE_KEYS or item is None:
                continue
            normalized[key] = canonicalize(item, parent_key=key)
        return normalized
    if isinstance(value, list):
        normalized_list = [canonicalize(item) for item in value]
        if parent_key == "rules" and all(isinstance(item, dict) for item in normalized_list):
            return sorted(
                normalized_list,
                key=lambda item: (item.get("uid", ""), item.get("title", "")),
            )
        if parent_key == "data" and all(isinstance(item, dict) for item in normalized_list):
            return sorted(normalized_list, key=lambda item: item.get("refId", ""))
        return normalized_list
    if value == "-100":
        return "__expr__"
    return value


def compare_group(
    name: str,
    desired: dict[str, Any],
    current: dict[str, Any] | None,
) -> Comparison:
    if current is None:
        return Comparison(group=name, action="create", diff="")

    desired_text = json.dumps(canonicalize(desired), indent=2, sort_keys=True).splitlines()
    current_text = json.dumps(canonicalize(current), indent=2, sort_keys=True).splitlines()
    if desired_text == current_text:
        return Comparison(group=name, action="no-change", diff="")

    diff = "\n".join(
        difflib.unified_diff(
            current_text,
            desired_text,
            fromfile=f"live/{name}.json",
            tofile=f"desired/{name}.json",
            lineterm="",
        )
    )
    return Comparison(group=name, action="update", diff=diff + "\n")

