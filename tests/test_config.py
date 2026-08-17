from pathlib import Path

import pytest

from grafana_alerts.config import load_site
from grafana_alerts.exceptions import ConfigError


def test_load_example_site() -> None:
    site = load_site("sites/example.yaml")

    assert site.name == "example"
    assert site.grafana["org_id"] == 1
    assert site.groups[0].name == "host-health"


def test_duplicate_group_names_are_rejected(tmp_path: Path) -> None:
    site_file = tmp_path / "duplicate.yaml"
    site_file.write_text(
        """
site: duplicate
grafana:
  org_id: 1
  folder_uid: alerts
  datasource_uid: prometheus
groups:
  - name: same
    template: one.yaml.j2
  - name: same
    template: two.yaml.j2
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="Duplicate group name"):
        load_site(site_file)

