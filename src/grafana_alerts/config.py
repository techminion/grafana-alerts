from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from grafana_alerts.exceptions import ConfigError


@dataclass(frozen=True)
class GroupConfig:
    name: str
    template: str
    values: dict[str, Any]


@dataclass(frozen=True)
class SiteConfig:
    path: Path
    name: str
    grafana: dict[str, Any]
    defaults: dict[str, Any]
    labels: dict[str, str]
    groups: tuple[GroupConfig, ...]

    def template_context(self, group: GroupConfig) -> dict[str, Any]:
        return {
            "site": self.name,
            "grafana": self.grafana,
            "defaults": self.defaults,
            "labels": self.labels,
            "group": group.values,
        }


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ConfigError(f"Site config does not exist: {path}")

    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc

    if not isinstance(loaded, dict):
        raise ConfigError(f"Site config must contain a YAML mapping: {path}")
    return loaded


def load_site(path: str | Path) -> SiteConfig:
    site_path = Path(path).resolve()
    raw = _load_yaml(site_path)

    required = ("site", "grafana", "groups")
    missing = [key for key in required if key not in raw]
    if missing:
        raise ConfigError(f"Missing required site keys: {', '.join(missing)}")

    if not isinstance(raw["site"], str) or not raw["site"].strip():
        raise ConfigError("site must be a non-empty string")
    if not isinstance(raw["grafana"], dict):
        raise ConfigError("grafana must be a mapping")
    if not isinstance(raw["groups"], list) or not raw["groups"]:
        raise ConfigError("groups must be a non-empty list")

    grafana_required = ("org_id", "folder_uid")
    missing_grafana = [key for key in grafana_required if key not in raw["grafana"]]
    if missing_grafana:
        raise ConfigError(f"Missing required grafana keys: {', '.join(missing_grafana)}")
    datasource_uid = raw["grafana"].get("datasource_uid")
    datasources = raw["grafana"].get("datasources")
    if not datasource_uid and not isinstance(datasources, dict):
        raise ConfigError("grafana must define datasource_uid or a datasources mapping")
    if isinstance(datasources, dict) and not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in datasources.items()
    ):
        raise ConfigError("grafana.datasources must be a string-to-string mapping")

    groups: list[GroupConfig] = []
    seen_names: set[str] = set()
    for index, item in enumerate(raw["groups"]):
        if not isinstance(item, dict):
            raise ConfigError(f"groups[{index}] must be a mapping")
        name = item.get("name")
        template = item.get("template")
        if not isinstance(name, str) or not name:
            raise ConfigError(f"groups[{index}].name must be a non-empty string")
        if name in seen_names:
            raise ConfigError(f"Duplicate group name: {name}")
        if not isinstance(template, str) or not template:
            raise ConfigError(f"groups[{index}].template must be a non-empty string")
        seen_names.add(name)
        values = {key: value for key, value in item.items() if key not in {"name", "template"}}
        values["name"] = name
        groups.append(GroupConfig(name=name, template=template, values=values))

    labels = raw.get("labels", {})
    defaults = raw.get("defaults", {})
    if not isinstance(labels, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in labels.items()
    ):
        raise ConfigError("labels must be a string-to-string mapping")
    if not isinstance(defaults, dict):
        raise ConfigError("defaults must be a mapping")

    return SiteConfig(
        path=site_path,
        name=raw["site"],
        grafana=raw["grafana"],
        defaults=defaults,
        labels=labels,
        groups=tuple(groups),
    )
