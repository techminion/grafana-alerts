from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from grafana_alerts.config import load_site
from grafana_alerts.exceptions import AlertManagerError
from grafana_alerts.grafana import GrafanaClient
from grafana_alerts.renderer import render_site, write_rendered

app = typer.Typer(no_args_is_help=True, help="Render, validate, and deploy Grafana alerts.")
console = Console()


def _render(site_file: Path, template_dir: Path):
    site = load_site(site_file)
    return site, render_site(site, template_dir)


@app.command()
def validate(
    site_file: Annotated[Path, typer.Argument(exists=True, readable=True)],
    template_dir: Annotated[Path, typer.Option("--templates", "-t")] = Path("templates"),
) -> None:
    """Render a site in memory and validate every rule group."""
    try:
        site, groups = _render(site_file, template_dir)
    except AlertManagerError as exc:
        console.print(f"[red]Validation failed:[/red] {exc}")
        raise typer.Exit(1) from exc
    console.print(f"[green]Valid:[/green] {site.name} ({len(groups)} rule group(s))")


@app.command()
def render(
    site_file: Annotated[Path, typer.Argument(exists=True, readable=True)],
    template_dir: Annotated[Path, typer.Option("--templates", "-t")] = Path("templates"),
    output_dir: Annotated[Path, typer.Option("--output", "-o")] = Path("build"),
) -> None:
    """Render a site into deterministic Grafana API JSON payloads."""
    try:
        site, groups = _render(site_file, template_dir)
        paths = write_rendered(groups, output_dir / site.name)
    except AlertManagerError as exc:
        console.print(f"[red]Render failed:[/red] {exc}")
        raise typer.Exit(1) from exc
    for path in paths:
        console.print(f"[green]Rendered[/green] {path}")


def _credentials() -> tuple[str, str]:
    url = os.getenv("GRAFANA_URL", "")
    token = os.getenv("GRAFANA_TOKEN", "")
    if not url or not token:
        raise AlertManagerError("GRAFANA_URL and GRAFANA_TOKEN must be set")
    return url, token


def _assert_remote_ready(folder_uid: object) -> None:
    if str(folder_uid).startswith("REPLACE_WITH_"):
        raise AlertManagerError(
            "Replace the placeholder grafana.folder_uid in the site config before remote access"
        )


@app.command()
def whoami() -> None:
    """Show the identity represented by the configured Grafana token."""
    try:
        url, token = _credentials()
        identity = GrafanaClient(url, token).whoami()
    except AlertManagerError as exc:
        console.print(f"[red]Authentication failed:[/red] {exc}")
        raise typer.Exit(1) from exc
    console.print_json(json.dumps(identity))


@app.command()
def plan(
    site_file: Annotated[Path, typer.Argument(exists=True, readable=True)],
    template_dir: Annotated[Path, typer.Option("--templates", "-t")] = Path("templates"),
) -> None:
    """Compare desired groups with Grafana without changing Grafana."""
    try:
        site, groups = _render(site_file, template_dir)
        _assert_remote_ready(site.grafana["folder_uid"])
        url, token = _credentials()
        client = GrafanaClient(url, token)
        client.whoami()
        table = Table("Group", "Action")
        for group in groups:
            current = client.get_group(site.grafana["folder_uid"], group.name)
            action = "create" if current is None else "update"
            table.add_row(group.name, action)
    except AlertManagerError as exc:
        console.print(f"[red]Plan failed:[/red] {exc}")
        raise typer.Exit(1) from exc
    console.print(table)


@app.command()
def deploy(
    site_file: Annotated[Path, typer.Argument(exists=True, readable=True)],
    template_dir: Annotated[Path, typer.Option("--templates", "-t")] = Path("templates"),
) -> None:
    """Create or replace configured rule groups in Grafana."""
    try:
        site, groups = _render(site_file, template_dir)
        _assert_remote_ready(site.grafana["folder_uid"])
        url, token = _credentials()
        client = GrafanaClient(url, token)
        identity = client.whoami()
        console.print(
            "Authenticated as "
            f"[bold]{identity.get('login') or identity.get('name') or identity.get('email')}[/bold]"
        )
        for group in groups:
            result = client.apply_group(site.grafana["folder_uid"], group.name, group.payload)
            console.print(f"[green]Applied[/green] {result.group} (HTTP {result.status_code})")
    except AlertManagerError as exc:
        console.print(f"[red]Deploy failed:[/red] {exc}")
        raise typer.Exit(1) from exc
