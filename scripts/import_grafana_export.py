#!/usr/bin/env python3
"""Convert a Grafana file-provisioning export into reusable group templates."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import yaml

SITE_MARKER = "__SITE_NAME__"
ENVIRONMENT_MARKER = "__ENVIRONMENT__"


def parse_mapping(value: str) -> tuple[str, str]:
    try:
        name, uid = value.split("=", 1)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected NAME=UID") from exc
    if not name or not uid:
        raise argparse.ArgumentTypeError("expected non-empty NAME=UID")
    return name, uid


def duration_seconds(value: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]*)(s|m|h)", value)
    if not match:
        raise ValueError(f"Unsupported group interval: {value}")
    number = int(match.group(1))
    return number * {"s": 1, "m": 60, "h": 3600}[match.group(2)]


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def transform_strings(
    value: Any,
    *,
    site_name: str,
    environment: str,
    datasource_tokens: dict[str, str],
) -> Any:
    if isinstance(value, str):
        if value in datasource_tokens:
            return datasource_tokens[value]
        return value.replace(site_name, SITE_MARKER).replace(environment, ENVIRONMENT_MARKER)
    if isinstance(value, list):
        return [
            transform_strings(
                item,
                site_name=site_name,
                environment=environment,
                datasource_tokens=datasource_tokens,
            )
            for item in value
        ]
    if isinstance(value, dict):
        return {
            key: transform_strings(
                item,
                site_name=site_name,
                environment=environment,
                datasource_tokens=datasource_tokens,
            )
            for key, item in value.items()
        }
    return value


def template_text(
    group: dict[str, Any],
    *,
    site_name: str,
    environment: str,
    datasource_tokens: dict[str, str],
) -> str:
    rules = []
    for exported_rule in group["rules"]:
        rule = {
            key: value
            for key, value in exported_rule.items()
            if key not in {"id", "updated", "provenance"}
        }
        # File exports may omit `for` when the pending duration is zero. The
        # create/update API expects the duration to be explicit.
        rule.setdefault("for", "0s")
        rule["ruleGroup"] = "@@GROUP_NAME@@"
        rule["folderUID"] = "@@FOLDER_UID@@"
        rule["orgId"] = "@@ORG_ID@@"
        rules.append(
            transform_strings(
                rule,
                site_name=site_name,
                environment=environment,
                datasource_tokens=datasource_tokens,
            )
        )

    payload = {
        "title": "@@GROUP_NAME@@",
        "folderUid": "@@FOLDER_UID@@",
        "interval": duration_seconds(group["interval"]),
        "rules": rules,
    }
    rendered = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    replacements = {
        json.dumps("@@GROUP_NAME@@"): "[[ group.name | tojson ]]",
        json.dumps("@@FOLDER_UID@@"): "[[ grafana.folder_uid | tojson ]]",
        json.dumps("@@ORG_ID@@"): "[[ grafana.org_id ]]",
    }
    for datasource_name in set(datasource_tokens.values()):
        replacements[json.dumps(datasource_name)] = (
            f"[[ grafana.datasources.{datasource_name.removeprefix('@@DS_').removesuffix('@@')} "
            "| tojson ]]"
        )
    for before, after in replacements.items():
        rendered = rendered.replace(before, after)
    return rendered


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path)
    parser.add_argument("--site-name", required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--folder-uid", default="REPLACE_WITH_FOLDER_UID")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--site-config", type=Path, required=True)
    parser.add_argument(
        "--datasource",
        action="append",
        type=parse_mapping,
        required=True,
        metavar="NAME=UID",
    )
    args = parser.parse_args()

    exported = json.loads(args.export.read_text(encoding="utf-8"))
    groups = exported.get("groups")
    if exported.get("apiVersion") != 1 or not isinstance(groups, list) or not groups:
        raise SystemExit("Expected a Grafana apiVersion: 1 export with non-empty groups")

    datasource_by_name = dict(args.datasource)
    datasource_tokens = {
        uid: f"@@DS_{name}@@" for name, uid in datasource_by_name.items()
    }
    org_ids = {group["orgId"] for group in groups}
    if len(org_ids) != 1:
        raise SystemExit(f"Expected one orgId, found {sorted(org_ids)}")

    args.output.mkdir(parents=True, exist_ok=True)
    configured_groups = []
    for group in groups:
        filename = f"{slug(group['name'])}.json.j2"
        (args.output / filename).write_text(
            template_text(
                group,
                site_name=args.site_name,
                environment=args.environment,
                datasource_tokens=datasource_tokens,
            ),
            encoding="utf-8",
        )
        configured_groups.append(
            {
                "name": group["name"],
                "template": f"imported/{slug(args.site_name)}/{filename}",
            }
        )

    site_config = {
        "site": args.site_name,
        "grafana": {
            "org_id": next(iter(org_ids)),
            "folder_uid": args.folder_uid,
            "datasources": datasource_by_name,
        },
        "defaults": {"environment": args.environment},
        "labels": {},
        "groups": configured_groups,
    }
    args.site_config.parent.mkdir(parents=True, exist_ok=True)
    args.site_config.write_text(
        yaml.safe_dump(site_config, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    print(f"Imported {sum(len(group['rules']) for group in groups)} rules in {len(groups)} groups")


if __name__ == "__main__":
    main()
