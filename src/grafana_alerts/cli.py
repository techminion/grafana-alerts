from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from grafana_alerts.artifacts import load_bundle, write_bundle
from grafana_alerts.builder import (
    AlertDefinition,
    generated_uid,
    prometheus_selector,
    slugify,
    write_site_with_alert,
)
from grafana_alerts.config import load_site
from grafana_alerts.deployment_plan import (
    collect_prune_candidates,
    load_plan,
    verify_live_prune_candidates,
    write_plan,
)
from grafana_alerts.exceptions import AlertManagerError
from grafana_alerts.grafana import GrafanaClient
from grafana_alerts.preflight import PreflightReport, run_preflight
from grafana_alerts.receipt import (
    ReceiptRecorder,
    ensure_receipt_target_available,
    load_and_verify_receipt,
    sha256_file,
    write_receipt,
)
from grafana_alerts.renderer import render_site
from grafana_alerts.semantic import compare_group

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
        bundle = write_bundle(site, groups, output_dir)
    except AlertManagerError as exc:
        console.print(f"[red]Render failed:[/red] {exc}")
        raise typer.Exit(1) from exc
    for group in bundle.groups:
        console.print(f"[green]Rendered[/green] {bundle.directory / group.filename}")
    console.print(f"[green]Manifest[/green] {bundle.directory / 'manifest.json'}")


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


def _authenticated_client() -> GrafanaClient:
    url, token = _credentials()
    client = GrafanaClient(url, token)
    client.whoami()
    return client


def _site_preflight(site) -> tuple[GrafanaClient, PreflightReport]:
    url, token = _credentials()
    client = GrafanaClient(url, token)
    return client, run_preflight(site, client)


def _filtered(values: list[str], search: str | None, limit: int) -> list[str]:
    if search:
        needle = search.casefold()
        values = [value for value in values if needle in value.casefold()]
    return sorted(values)[:limit]


def _print_values(title: str, values: list[str], json_output: bool) -> None:
    if json_output:
        console.print_json(json.dumps(values))
        return
    table = Table(title)
    for value in values:
        table.add_row(value)
    console.print(table)


def _numbered_choice(
    prompt: str,
    values: list[str],
    *,
    default: int = 1,
) -> str:
    if not values:
        raise AlertManagerError(f"No values are available for {prompt.casefold()}")
    table = Table("#", prompt)
    for index, value in enumerate(values, start=1):
        table.add_row(str(index), value)
    console.print(table)
    while True:
        choice = typer.prompt(f"{prompt} number", default=default)
        try:
            return values[int(choice) - 1]
        except (ValueError, IndexError):
            console.print(f"[red]Choose a number from 1 to {len(values)}.[/red]")


def _choose_datasource(
    sources: list[dict[str, object]],
    requested_uid: str | None,
    configured_uid: object,
) -> str:
    prometheus_sources = [
        source for source in sources if source.get("type") == "prometheus" and source.get("uid")
    ]
    if requested_uid:
        selected = next(
            (source for source in prometheus_sources if source.get("uid") == requested_uid),
            None,
        )
        if selected is None:
            raise AlertManagerError(
                f"Prometheus data source {requested_uid!r} is not visible to this Grafana token"
            )
        return requested_uid
    if not prometheus_sources:
        raise AlertManagerError("No Prometheus data sources are visible to this Grafana token")

    labels = [
        f"{source.get('name', '')} ({source['uid']})" for source in prometheus_sources
    ]
    default = next(
        (
            index
            for index, source in enumerate(prometheus_sources, start=1)
            if source.get("uid") == configured_uid
        ),
        1,
    )
    selected_label = _numbered_choice("Prometheus data source", labels, default=default)
    return str(prometheus_sources[labels.index(selected_label)]["uid"])


def _choose_metric(client: GrafanaClient, datasource_uid: str) -> str:
    metrics = client.prometheus_metrics(datasource_uid)
    while True:
        search = typer.prompt("Metric search", default="up")
        matches = _filtered(metrics, search, 25)
        if matches:
            return _numbered_choice("Metric", matches)
        console.print(f"[yellow]No metrics matched {search!r}; try another search.[/yellow]")


def _prompt_matchers(
    client: GrafanaClient,
    datasource_uid: str,
    metric: str,
) -> list[tuple[str, str, str]]:
    labels = sorted(
        label
        for label in client.prometheus_labels(datasource_uid, metric=metric)
        if label != "__name__"
    )
    matchers: list[tuple[str, str, str]] = []
    while labels and typer.confirm("Add a label matcher?", default=False):
        label = _numbered_choice("Label", labels)
        values = sorted(
            client.prometheus_label_values(datasource_uid, label, metric=metric)
        )[:25]
        if values:
            _print_values(f"Known {label} values (first 25)", values, False)
        operator = typer.prompt("Matcher operator (=, !=, =~, !~)", default="=")
        value = typer.prompt("Matcher value")
        matchers.append((label, operator, value))
    return matchers


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
def preflight(
    site_file: Annotated[Path, typer.Argument(exists=True, readable=True)],
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON output.")] = False,
) -> None:
    """Verify token organization, folder, and data sources for a site."""
    try:
        site = load_site(site_file)
        _assert_remote_ready(site.grafana["folder_uid"])
        _, report = _site_preflight(site)
    except AlertManagerError as exc:
        console.print(f"[red]Preflight failed:[/red] {exc}")
        raise typer.Exit(1) from exc

    if json_output:
        console.print_json(json.dumps(asdict(report)))
        return
    table = Table("Check", "Configured", "Grafana")
    table.add_row("identity", "token", report.identity)
    table.add_row(
        "organization", str(report.org_id), f"{report.org_id} ({report.org_name})"
    )
    table.add_row(
        "folder", report.folder_uid, f"{report.folder_uid} ({report.folder_title})"
    )
    for datasource in report.datasources:
        table.add_row(
            f"datasource:{datasource.key}",
            datasource.uid,
            f"{datasource.uid} ({datasource.name}, {datasource.type})",
        )
    console.print(table)
    console.print(f"[green]Preflight passed[/green] for {report.site}")


@app.command()
def datasources(
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON output.")] = False,
) -> None:
    """List data sources visible to the configured Grafana token."""
    try:
        sources = _authenticated_client().list_datasources()
    except AlertManagerError as exc:
        console.print(f"[red]Data source discovery failed:[/red] {exc}")
        raise typer.Exit(1) from exc
    if json_output:
        console.print_json(json.dumps(sources))
        return
    table = Table("Name", "UID", "Type", "Default")
    for source in sorted(sources, key=lambda item: str(item.get("name", ""))):
        table.add_row(
            str(source.get("name", "")),
            str(source.get("uid", "")),
            str(source.get("type", "")),
            "yes" if source.get("isDefault") else "",
        )
    console.print(table)


@app.command()
def metrics(
    datasource_uid: Annotated[str, typer.Option("--datasource", "-d")],
    search: Annotated[str | None, typer.Option(help="Case-insensitive name filter.")] = None,
    limit: Annotated[int, typer.Option(min=1, help="Maximum results to display.")] = 200,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON output.")] = False,
) -> None:
    """Discover Prometheus metric names through Grafana."""
    try:
        values = _filtered(
            _authenticated_client().prometheus_metrics(datasource_uid), search, limit
        )
    except AlertManagerError as exc:
        console.print(f"[red]Metric discovery failed:[/red] {exc}")
        raise typer.Exit(1) from exc
    _print_values("Metric", values, json_output)


@app.command()
def labels(
    datasource_uid: Annotated[str, typer.Option("--datasource", "-d")],
    metric: Annotated[str | None, typer.Option(help="Scope labels to this metric.")] = None,
    search: Annotated[str | None, typer.Option(help="Case-insensitive name filter.")] = None,
    limit: Annotated[int, typer.Option(min=1, help="Maximum results to display.")] = 200,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON output.")] = False,
) -> None:
    """Discover Prometheus label names through Grafana."""
    try:
        values = _filtered(
            _authenticated_client().prometheus_labels(datasource_uid, metric=metric),
            search,
            limit,
        )
    except AlertManagerError as exc:
        console.print(f"[red]Label discovery failed:[/red] {exc}")
        raise typer.Exit(1) from exc
    _print_values("Label", values, json_output)


@app.command("label-values")
def label_values(
    label: Annotated[str, typer.Argument(help="Prometheus label name.")],
    datasource_uid: Annotated[str, typer.Option("--datasource", "-d")],
    metric: Annotated[str | None, typer.Option(help="Scope values to this metric.")] = None,
    search: Annotated[str | None, typer.Option(help="Case-insensitive value filter.")] = None,
    limit: Annotated[int, typer.Option(min=1, help="Maximum results to display.")] = 200,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON output.")] = False,
) -> None:
    """Discover values for a Prometheus label through Grafana."""
    try:
        values = _filtered(
            _authenticated_client().prometheus_label_values(
                datasource_uid, label, metric=metric
            ),
            search,
            limit,
        )
    except AlertManagerError as exc:
        console.print(f"[red]Label value discovery failed:[/red] {exc}")
        raise typer.Exit(1) from exc
    _print_values("Value", values, json_output)


@app.command("test-query")
def test_query(
    datasource_uid: Annotated[str, typer.Option("--datasource", "-d")],
    expression: Annotated[str, typer.Option("--expr", help="PromQL expression to test.")],
    time: Annotated[
        str | None,
        typer.Option(help="Optional RFC3339 or Unix evaluation timestamp."),
    ] = None,
) -> None:
    """Run an instant PromQL query through Grafana and print its result."""
    try:
        result = _authenticated_client().query_prometheus(
            datasource_uid, expression, time=time
        )
    except AlertManagerError as exc:
        console.print(f"[red]PromQL query failed:[/red] {exc}")
        raise typer.Exit(1) from exc
    console.print_json(json.dumps(result))


@app.command("create-alert")
def create_alert(
    site_file: Annotated[Path, typer.Argument(exists=True, readable=True)],
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    template_dir: Annotated[Path, typer.Option("--templates", "-t")] = Path("templates"),
    datasource_uid: Annotated[
        str | None, typer.Option("--datasource", "-d")
    ] = None,
    metric: Annotated[str | None, typer.Option(help="Metric used to build a selector.")] = None,
    expression: Annotated[str | None, typer.Option("--expr", help="PromQL expression.")] = None,
    group_name: Annotated[str | None, typer.Option("--group")] = None,
    title: Annotated[str | None, typer.Option()] = None,
    uid: Annotated[str | None, typer.Option()] = None,
    threshold: Annotated[float | None, typer.Option()] = None,
    evaluator: Annotated[str | None, typer.Option(help="gt or lt.")] = None,
    reducer: Annotated[str | None, typer.Option(help="last, avg, min, max, or sum.")] = None,
    pending_for: Annotated[str | None, typer.Option("--pending-for")] = None,
    severity: Annotated[str | None, typer.Option()] = None,
    summary: Annotated[str | None, typer.Option()] = None,
    description: Annotated[str | None, typer.Option()] = None,
    force: Annotated[bool, typer.Option(help="Replace an existing output file.")] = False,
) -> None:
    """Interactively discover, test, and generate a Prometheus alert site config."""
    try:
        site = load_site(site_file)
        client = _authenticated_client()
        selected_datasource = _choose_datasource(
            client.list_datasources(), datasource_uid, site.grafana.get("datasource_uid")
        )

        selected_metric = metric
        if expression is None:
            selected_metric = selected_metric or _choose_metric(client, selected_datasource)
            matchers = _prompt_matchers(client, selected_datasource, selected_metric)
            expression = typer.prompt(
                "PromQL expression",
                default=prometheus_selector(selected_metric, matchers),
            )

        query_result = client.query_prometheus(selected_datasource, expression)
        result_type = query_result.get("resultType", "unknown")
        result = query_result.get("result", [])
        result_count = len(result) if isinstance(result, list) else 0
        console.print(
            f"[green]PromQL valid:[/green] {result_type}, {result_count} result(s)"
        )

        default_title = f"{selected_metric or 'PromQL'} alert"
        title = title or typer.prompt("Alert title", default=default_title)
        group_name = group_name or typer.prompt(
            "Rule group name", default=f"generated-{slugify(title)}"
        )
        uid = uid or typer.prompt("Rule UID", default=generated_uid(title))
        threshold = threshold if threshold is not None else typer.prompt(
            "Threshold", default=1.0, type=float
        )
        evaluator = evaluator or typer.prompt("Evaluator (gt or lt)", default="gt")
        reducer = reducer or typer.prompt(
            "Reducer (last, avg, min, max, or sum)", default="last"
        )
        pending_for = pending_for or typer.prompt("Pending duration", default="5m")
        severity = severity or typer.prompt("Severity", default="warning")
        summary = summary or typer.prompt("Summary", default=title)
        description = description or typer.prompt(
            "Description",
            default=f"{title}. Current value: {{{{ $values.B.Value }}}}",
        )

        defaults = site.defaults
        definition = AlertDefinition(
            group_name=group_name,
            uid=uid,
            title=title,
            datasource_uid=selected_datasource,
            expression=expression,
            threshold=threshold,
            evaluator=evaluator,
            reducer=reducer,
            pending_for=pending_for,
            severity=severity,
            summary=summary,
            description=description,
            evaluation_interval_seconds=int(
                defaults.get("evaluation_interval_seconds", 60)
            ),
            query_window_seconds=int(defaults.get("query_window_seconds", 600)),
            no_data_state=str(defaults.get("no_data_state", "NoData")),
            exec_error_state=str(defaults.get("exec_error_state", "Error")),
        )
        destination = output or site_file.with_name(
            f"{site_file.stem}-{slugify(group_name)}.yaml"
        )
        generated = write_site_with_alert(
            site_file, destination, definition, template_dir, overwrite=force
        )
    except AlertManagerError as exc:
        console.print(f"[red]Alert creation failed:[/red] {exc}")
        raise typer.Exit(1) from exc
    console.print(f"[green]Generated and validated[/green] {generated}")
    console.print(f"Next: grafana-alerts render {generated} --output build")


@app.command()
def plan(
    site_file: Annotated[Path, typer.Argument(exists=True, readable=True)],
    artifact_dir: Annotated[
        Path,
        typer.Option("--artifact-dir", exists=True, file_okay=False, readable=True),
    ] = ...,
    output_dir: Annotated[Path, typer.Option("--output", "-o")] = Path("plan"),
    prune: Annotated[
        bool,
        typer.Option(help="Plan deletion only for absent, explicitly allowlisted groups."),
    ] = False,
) -> None:
    """Compare a rendered artifact with Grafana without changing Grafana."""
    try:
        site = load_site(site_file)
        _assert_remote_ready(site.grafana["folder_uid"])
        bundle = load_bundle(site, artifact_dir)
        client, _ = _site_preflight(site)
        table = Table("Group", "Action")
        comparisons = []
        for group in bundle.groups:
            current = client.get_group(site.grafana["folder_uid"], group.name)
            comparison = compare_group(group.name, group.payload, current)
            comparisons.append(comparison)
            table.add_row(group.name, comparison.action)
        prune_candidates = (
            collect_prune_candidates(site, bundle, client) if prune else ()
        )
        for candidate in prune_candidates:
            table.add_row(candidate.name, "delete (allowlisted)")
        plan_path = write_plan(
            comparisons, prune_candidates, site, bundle, output_dir
        )
    except AlertManagerError as exc:
        console.print(f"[red]Plan failed:[/red] {exc}")
        raise typer.Exit(1) from exc
    console.print(table)
    console.print(f"[green]Plan[/green] {plan_path}")


@app.command()
def deploy(
    site_file: Annotated[Path, typer.Argument(exists=True, readable=True)],
    artifact_dir: Annotated[
        Path,
        typer.Option("--artifact-dir", exists=True, file_okay=False, readable=True),
    ] = ...,
    prune_plan: Annotated[
        Path | None,
        typer.Option("--prune-plan", exists=True, dir_okay=False, readable=True),
    ] = None,
    confirm_prune: Annotated[
        str | None,
        typer.Option(
            "--confirm-prune",
            help='Must equal "DELETE ALLOWLISTED GROUPS" to execute a prune plan.',
        ),
    ] = None,
    receipt: Annotated[
        Path | None,
        typer.Option(
            "--receipt",
            help="Write an exclusive deployment receipt and SHA-256 sidecar.",
        ),
    ] = None,
) -> None:
    """Verify and apply an exact rendered artifact to Grafana."""
    recorder = ReceiptRecorder()
    failure: AlertManagerError | None = None
    try:
        if receipt is not None:
            ensure_receipt_target_available(receipt)
        site = load_site(site_file)
        recorder.target(
            site.name, site.grafana["org_id"], str(site.grafana["folder_uid"])
        )
        _assert_remote_ready(site.grafana["folder_uid"])
        bundle = load_bundle(site, artifact_dir)
        recorder.artifact_manifest_sha256 = sha256_file(
            bundle.directory / "manifest.json"
        )
        client, preflight_report = _site_preflight(site)
        recorder.identity = preflight_report.identity
        deployment_plan = None
        if prune_plan is not None or confirm_prune is not None:
            if prune_plan is None:
                raise AlertManagerError("--confirm-prune requires --prune-plan")
            if confirm_prune != "DELETE ALLOWLISTED GROUPS":
                raise AlertManagerError(
                    '--confirm-prune must equal "DELETE ALLOWLISTED GROUPS"'
                )
            recorder.deployment_plan_sha256 = sha256_file(prune_plan)
            deployment_plan = load_plan(site, bundle, prune_plan)
            if deployment_plan.prune and os.getenv("PRUNE_ENABLED", "") != "true":
                raise AlertManagerError(
                    "PRUNE_ENABLED must equal true before allowlisted groups can be deleted"
                )
            verify_live_prune_candidates(site, deployment_plan, client)
        console.print(
            "Authenticated as "
            f"[bold]{preflight_report.identity}[/bold] in organization "
            f"[bold]{preflight_report.org_id}[/bold]"
        )
        for group in bundle.groups:
            try:
                result = client.apply_group(
                    site.grafana["folder_uid"], group.name, group.payload
                )
            except AlertManagerError as exc:
                recorder.record(group.name, "apply", "failed", error=str(exc))
                raise
            recorder.record(
                result.group, "apply", "succeeded", http_status=result.status_code
            )
            console.print(f"[green]Applied[/green] {result.group} (HTTP {result.status_code})")
        if deployment_plan is not None:
            for candidate in deployment_plan.prune:
                try:
                    result = client.delete_group(
                        site.grafana["folder_uid"], candidate.name
                    )
                except AlertManagerError as exc:
                    recorder.record(candidate.name, "delete", "failed", error=str(exc))
                    raise
                recorder.record(
                    result.group, "delete", "succeeded", http_status=result.status_code
                )
                console.print(
                    f"[red]Deleted allowlisted group[/red] {result.group} "
                    f"(HTTP {result.status_code})"
                )
    except AlertManagerError as exc:
        failure = exc

    if receipt is not None:
        try:
            status = "failed" if failure else "succeeded"
            write_receipt(
                receipt,
                recorder.payload(status, str(failure) if failure else None),
            )
            console.print(f"[green]Deployment receipt[/green] {receipt}")
        except AlertManagerError as exc:
            if failure is None:
                failure = exc
            else:
                console.print(f"[red]Receipt failed:[/red] {exc}")

    if failure is not None:
        console.print(f"[red]Deploy failed:[/red] {failure}")
        raise typer.Exit(1) from failure


@app.command("verify-receipt")
def verify_receipt(
    receipt_file: Annotated[Path, typer.Argument(exists=True, readable=True)],
) -> None:
    """Validate a deployment receipt and its SHA-256 sidecar."""
    try:
        payload = load_and_verify_receipt(receipt_file)
    except AlertManagerError as exc:
        console.print(f"[red]Receipt verification failed:[/red] {exc}")
        raise typer.Exit(1) from exc
    console.print(
        f"[green]Valid {payload['status']} deployment receipt[/green] "
        f"for {payload['site'] or 'unknown site'}"
    )
