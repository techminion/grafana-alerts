import json
from pathlib import Path

import pytest

from grafana_alerts.artifacts import load_bundle, write_bundle
from grafana_alerts.config import load_site
from grafana_alerts.exceptions import ConfigError
from grafana_alerts.renderer import render_site


def test_bundle_manifest_is_deterministic_and_loadable(tmp_path: Path) -> None:
    site = load_site("sites/example.yaml")
    groups = render_site(site, "templates")

    first = write_bundle(site, groups, tmp_path / "first")
    second = write_bundle(site, groups, tmp_path / "second")
    loaded = load_bundle(site, tmp_path / "first")

    assert (first.directory / "manifest.json").read_bytes() == (
        second.directory / "manifest.json"
    ).read_bytes()
    assert loaded.site == "example"
    assert loaded.groups[0].payload == groups[0].payload
    manifest = json.loads((first.directory / "manifest.json").read_text())
    assert len(manifest["groups"][0]["sha256"]) == 64


def test_bundle_rejects_tampered_group(tmp_path: Path) -> None:
    site = load_site("sites/example.yaml")
    bundle = write_bundle(site, render_site(site, "templates"), tmp_path)
    group_path = bundle.directory / bundle.groups[0].filename
    group_path.write_text(group_path.read_text() + "\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="hash mismatch"):
        load_bundle(site, bundle.directory)


def test_bundle_rejects_wrong_site_identity(tmp_path: Path) -> None:
    example = load_site("sites/example.yaml")
    sbcp = load_site("sites/sbcp.yaml")
    bundle = write_bundle(example, render_site(example, "templates"), tmp_path)

    with pytest.raises(ConfigError, match="identity does not match"):
        load_bundle(sbcp, bundle.directory)
