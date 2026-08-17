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
