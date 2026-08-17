from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined, TemplateError

from grafana_alerts.config import SiteConfig
from grafana_alerts.exceptions import ConfigError
from grafana_alerts.validator import validate_group


@dataclass(frozen=True)
class RenderedGroup:
    name: str
    payload: dict[str, Any]


def _replace_markers(value: Any, replacements: dict[str, str]) -> Any:
    if isinstance(value, str):
        for marker, replacement in replacements.items():
            value = value.replace(marker, replacement)
        return value
    if isinstance(value, list):
        return [_replace_markers(item, replacements) for item in value]
    if isinstance(value, dict):
        return {
            _replace_markers(key, replacements): _replace_markers(item, replacements)
            for key, item in value.items()
        }
    return value


def _deep_merge(target: dict[str, Any], patch: dict[str, Any]) -> None:
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _deep_merge(target[key], value)
        else:
            target[key] = value


def _find_query(rule: dict[str, Any], ref_id: str) -> dict[str, Any]:
    for query in rule.get("data", []):
        if query.get("refId") == ref_id:
            return query
    raise ConfigError(f"Rule {rule.get('uid')} has no query with refId {ref_id}")


def _apply_group_overrides(payload: dict[str, Any], values: dict[str, Any]) -> None:
    thresholds = values.get("thresholds", {})
    for_overrides = values.get("for_overrides", {})
    query_overrides = values.get("query_overrides", {})
    rule_overrides = values.get("rule_overrides", {})

    for option_name, option in (
        ("thresholds", thresholds),
        ("for_overrides", for_overrides),
        ("query_overrides", query_overrides),
        ("rule_overrides", rule_overrides),
    ):
        if not isinstance(option, dict):
            raise ConfigError(f"group.{option_name} must be a mapping")

    rules_by_uid = {rule["uid"]: rule for rule in payload["rules"]}
    overridden_uids = (
        thresholds.keys()
        | for_overrides.keys()
        | query_overrides.keys()
        | rule_overrides.keys()
    )
    unknown = overridden_uids - rules_by_uid.keys()
    if unknown:
        raise ConfigError(f"Overrides reference unknown rule UIDs: {', '.join(sorted(unknown))}")

    for uid, params in thresholds.items():
        if not isinstance(params, list):
            raise ConfigError(f"Threshold override for {uid} must be a list")
        rule = rules_by_uid[uid]
        condition_query = _find_query(rule, rule["condition"])
        conditions = condition_query.get("model", {}).get("conditions", [])
        if not conditions or "evaluator" not in conditions[0]:
            raise ConfigError(
                f"Rule {uid} condition {rule['condition']} does not expose evaluator params"
            )
        conditions[0]["evaluator"]["params"] = params

    for uid, duration in for_overrides.items():
        rules_by_uid[uid]["for"] = duration

    for uid, queries in query_overrides.items():
        if not isinstance(queries, dict):
            raise ConfigError(f"Query overrides for {uid} must be a refId-to-expression mapping")
        rule = rules_by_uid[uid]
        for ref_id, expression in queries.items():
            model = _find_query(rule, ref_id).setdefault("model", {})
            field = "expr" if "expr" in model else "expression"
            model[field] = expression

    for uid, rule_patch in rule_overrides.items():
        if not isinstance(rule_patch, dict):
            raise ConfigError(f"Rule override for {uid} must be a mapping")
        _deep_merge(rules_by_uid[uid], rule_patch)


def _environment(template_dir: Path) -> Environment:
    return Environment(
        loader=FileSystemLoader(str(template_dir)),
        undefined=StrictUndefined,
        autoescape=False,
        keep_trailing_newline=True,
        variable_start_string="[[",
        variable_end_string="]]",
    )


def render_site(site: SiteConfig, template_dir: str | Path) -> tuple[RenderedGroup, ...]:
    directory = Path(template_dir).resolve()
    if not directory.is_dir():
        raise ConfigError(f"Template directory does not exist: {directory}")

    environment = _environment(directory)
    rendered: list[RenderedGroup] = []
    for group in site.groups:
        try:
            template = environment.get_template(group.template)
            text = template.render(site.template_context(group))
            payload = yaml.safe_load(text)
        except (TemplateError, yaml.YAMLError) as exc:
            raise ConfigError(f"Unable to render group {group.name}: {exc}") from exc

        if not isinstance(payload, dict):
            raise ConfigError(f"Template {group.template} must render a YAML mapping")
        environment_name = site.defaults.get("environment")
        if "__ENVIRONMENT__" in text and not environment_name:
            raise ConfigError(
                f"Site {site.name} must define defaults.environment for template {group.template}"
            )
        payload = _replace_markers(
            payload,
            {
                "__SITE_NAME__": site.name,
                "__ENVIRONMENT__": str(environment_name or ""),
            },
        )
        _apply_group_overrides(payload, group.values)
        if payload.get("title") != group.name:
            raise ConfigError(
                f"Rendered group title {payload.get('title')!r} does not match {group.name!r}"
            )
        validate_group(payload)
        rendered.append(RenderedGroup(name=group.name, payload=payload))

    return tuple(rendered)


def write_rendered(groups: tuple[RenderedGroup, ...], output_dir: str | Path) -> list[Path]:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for group in groups:
        path = directory / f"{group.name}.json"
        path.write_text(
            json.dumps(group.payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        paths.append(path)
    return paths
