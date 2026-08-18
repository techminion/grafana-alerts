from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from grafana_alerts.config import SiteConfig
from grafana_alerts.exceptions import ConfigError


class PreflightClient(Protocol):
    def whoami(self) -> dict[str, Any]: ...

    def current_org(self) -> dict[str, Any]: ...

    def get_folder(self, folder_uid: str) -> dict[str, Any]: ...

    def get_datasource(self, datasource_uid: str) -> dict[str, Any]: ...


@dataclass(frozen=True)
class DatasourceCheck:
    key: str
    uid: str
    name: str
    type: str


@dataclass(frozen=True)
class PreflightReport:
    site: str
    identity: str
    org_id: int
    org_name: str
    folder_uid: str
    folder_title: str
    datasources: tuple[DatasourceCheck, ...]


def configured_datasources(site: SiteConfig) -> tuple[tuple[str, str], ...]:
    configured: list[tuple[str, str]] = []
    datasource_uid = site.grafana.get("datasource_uid")
    if isinstance(datasource_uid, str) and datasource_uid:
        configured.append(("default", datasource_uid))
    datasources = site.grafana.get("datasources")
    if isinstance(datasources, dict):
        configured.extend((str(key), str(uid)) for key, uid in sorted(datasources.items()))
    return tuple(configured)


def run_preflight(site: SiteConfig, client: PreflightClient) -> PreflightReport:
    identity = client.whoami()
    identity_name = str(
        identity.get("login")
        or identity.get("name")
        or identity.get("email")
        or "unknown"
    )

    org = client.current_org()
    actual_org_id = org.get("id")
    expected_org_id = site.grafana["org_id"]
    if actual_org_id != expected_org_id:
        raise ConfigError(
            "Grafana token organization does not match the site config: "
            f"expected {expected_org_id}, found {actual_org_id}"
        )

    expected_folder_uid = str(site.grafana["folder_uid"])
    folder = client.get_folder(expected_folder_uid)
    actual_folder_uid = folder.get("uid")
    if actual_folder_uid != expected_folder_uid:
        raise ConfigError(
            "Grafana folder does not match the site config: "
            f"expected {expected_folder_uid}, found {actual_folder_uid}"
        )

    datasource_checks: list[DatasourceCheck] = []
    for key, expected_uid in configured_datasources(site):
        datasource = client.get_datasource(expected_uid)
        actual_uid = datasource.get("uid")
        if actual_uid != expected_uid:
            raise ConfigError(
                f"Grafana data source {key} does not match the site config: "
                f"expected {expected_uid}, found {actual_uid}"
            )
        datasource_org_id = datasource.get("orgId")
        if datasource_org_id is not None and datasource_org_id != expected_org_id:
            raise ConfigError(
                f"Grafana data source {key} belongs to organization "
                f"{datasource_org_id}, expected {expected_org_id}"
            )
        datasource_checks.append(
            DatasourceCheck(
                key=key,
                uid=expected_uid,
                name=str(datasource.get("name", "")),
                type=str(datasource.get("type", "")),
            )
        )

    return PreflightReport(
        site=site.name,
        identity=identity_name,
        org_id=expected_org_id,
        org_name=str(org.get("name", "")),
        folder_uid=expected_folder_uid,
        folder_title=str(folder.get("title", "")),
        datasources=tuple(datasource_checks),
    )
