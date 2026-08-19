from __future__ import annotations

import hashlib
import time
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Protocol

from grafana_alerts.artifacts import ArtifactBundle
from grafana_alerts.deployment_plan import live_group_sha256
from grafana_alerts.exceptions import AlertManagerError
from grafana_alerts.semantic import compare_group


class VerificationClient(Protocol):
    def get_group(self, folder_uid: str, group: str) -> dict[str, Any] | None: ...

    def query_prometheus(
        self, datasource_uid: str, expression: str, *, time: str | None = None
    ) -> dict[str, Any]: ...


@dataclass(frozen=True)
class GroupCheck:
    group: str
    target_state: str
    status: str
    attempts: int
    desired_sha256: str | None = None
    live_sha256: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class QueryCheck:
    datasource_uid: str
    expression_sha256: str
    references: tuple[str, ...]
    status: str
    attempts: int
    result_type: str | None = None
    result_count: int | None = None
    error: str | None = None


@dataclass(frozen=True)
class VerificationReport:
    status: str
    groups: tuple[GroupCheck, ...]
    queries: tuple[QueryCheck, ...]

    def payload(self) -> dict[str, Any]:
        groups: list[dict[str, Any]] = []
        for check in self.groups:
            item: dict[str, Any] = {
                "group": check.group,
                "targetState": check.target_state,
                "status": check.status,
                "attempts": check.attempts,
            }
            if check.desired_sha256 is not None:
                item["desiredSha256"] = check.desired_sha256
            if check.live_sha256 is not None:
                item["liveSha256"] = check.live_sha256
            if check.error is not None:
                item["error"] = check.error
            groups.append(item)

        queries: list[dict[str, Any]] = []
        for check in self.queries:
            item = {
                "datasourceUid": check.datasource_uid,
                "expressionSha256": check.expression_sha256,
                "references": list(check.references),
                "status": check.status,
                "attempts": check.attempts,
            }
            if check.result_type is not None:
                item["resultType"] = check.result_type
            if check.result_count is not None:
                item["resultCount"] = check.result_count
            if check.error is not None:
                item["error"] = check.error
            queries.append(item)
        return {
            "status": self.status,
            "groups": groups,
            "queries": queries,
        }


def _expression_sha256(expression: str) -> str:
    return hashlib.sha256(expression.encode()).hexdigest()


def _prometheus_probes(
    bundle: ArtifactBundle,
    datasource_types: dict[str, str],
) -> dict[tuple[str, str], set[str]]:
    probes: dict[tuple[str, str], set[str]] = {}
    for group in bundle.groups:
        for rule in group.payload.get("rules", []):
            if not isinstance(rule, dict):
                continue
            rule_uid = str(rule.get("uid", "unknown"))
            for query in rule.get("data", []):
                if not isinstance(query, dict):
                    continue
                datasource_uid = query.get("datasourceUid")
                model = query.get("model")
                if not isinstance(datasource_uid, str) or not isinstance(model, dict):
                    continue
                if datasource_types.get(datasource_uid) != "prometheus":
                    continue
                expression = model.get("expr")
                ref_id = query.get("refId")
                if not isinstance(expression, str) or not expression.strip():
                    continue
                reference = f"{group.name}/{rule_uid}:{ref_id or 'unknown'}"
                probes.setdefault((datasource_uid, expression), set()).add(reference)
    return probes


def _verify_group(
    client: VerificationClient,
    folder_uid: str,
    name: str,
    desired: dict[str, Any] | None,
    *,
    attempts: int,
    delay_seconds: float,
) -> GroupCheck:
    target_state = "present" if desired is not None else "absent"
    desired_hash = live_group_sha256(desired) if desired is not None else None
    last_live_hash: str | None = None
    last_error: str | None = None
    for attempt in range(1, attempts + 1):
        try:
            current = client.get_group(folder_uid, name)
            last_live_hash = (
                live_group_sha256(current) if current is not None else None
            )
            if desired is None and current is None:
                return GroupCheck(name, target_state, "succeeded", attempt)
            if desired is not None and compare_group(name, desired, current).action == "no-change":
                return GroupCheck(
                    name,
                    target_state,
                    "succeeded",
                    attempt,
                    desired_sha256=desired_hash,
                    live_sha256=last_live_hash,
                )
            last_error = (
                "group still exists" if desired is None else "semantic mismatch"
            )
        except AlertManagerError as exc:
            last_error = str(exc)
        if attempt < attempts and delay_seconds:
            time.sleep(delay_seconds)
    return GroupCheck(
        name,
        target_state,
        "failed",
        attempts,
        desired_sha256=desired_hash,
        live_sha256=last_live_hash,
        error=last_error or "verification failed",
    )


def _verify_query(
    client: VerificationClient,
    datasource_uid: str,
    expression: str,
    references: set[str],
    *,
    attempts: int,
    delay_seconds: float,
) -> QueryCheck:
    last_error: str | None = None
    for attempt in range(1, attempts + 1):
        try:
            result = client.query_prometheus(datasource_uid, expression)
            result_type = result.get("resultType")
            values = result.get("result")
            if result_type not in {"vector", "matrix", "scalar", "string"}:
                raise ValueError(f"unexpected result type {result_type!r}")
            if "result" not in result:
                raise ValueError("response did not include a result")
            result_count = (
                len(values)
                if result_type in {"vector", "matrix"} and isinstance(values, list)
                else 1
            )
            return QueryCheck(
                datasource_uid,
                _expression_sha256(expression),
                tuple(sorted(references)),
                "succeeded",
                attempt,
                result_type=str(result_type),
                result_count=result_count,
            )
        except (AlertManagerError, ValueError) as exc:
            last_error = str(exc)
        if attempt < attempts and delay_seconds:
            time.sleep(delay_seconds)
    return QueryCheck(
        datasource_uid,
        _expression_sha256(expression),
        tuple(sorted(references)),
        "failed",
        attempts,
        error=last_error or "query verification failed",
    )


def verify_deployment(
    bundle: ArtifactBundle,
    folder_uid: str,
    datasource_types: dict[str, str],
    client: VerificationClient,
    *,
    expected_absent: Iterable[str] = (),
    attempts: int = 5,
    delay_seconds: float = 2.0,
    query_attempts: int = 1,
    query_workers: int = 8,
) -> VerificationReport:
    if attempts < 1:
        raise ValueError("verification attempts must be at least 1")
    if delay_seconds < 0:
        raise ValueError("verification delay cannot be negative")
    if query_attempts < 1:
        raise ValueError("query verification attempts must be at least 1")
    if query_workers < 1:
        raise ValueError("query verification workers must be at least 1")

    group_checks = [
        _verify_group(
            client,
            folder_uid,
            group.name,
            group.payload,
            attempts=attempts,
            delay_seconds=delay_seconds,
        )
        for group in bundle.groups
    ]
    desired_names = {group.name for group in bundle.groups}
    for name in sorted(set(expected_absent) - desired_names):
        group_checks.append(
            _verify_group(
                client,
                folder_uid,
                name,
                None,
                attempts=attempts,
                delay_seconds=delay_seconds,
            )
        )

    probes = sorted(_prometheus_probes(bundle, datasource_types).items())

    def run_probe(
        item: tuple[tuple[str, str], set[str]],
    ) -> QueryCheck:
        (datasource_uid, expression), references = item
        return _verify_query(
            client,
            datasource_uid,
            expression,
            references,
            attempts=query_attempts,
            delay_seconds=delay_seconds,
        )

    with ThreadPoolExecutor(max_workers=min(query_workers, len(probes) or 1)) as executor:
        query_checks = list(executor.map(run_probe, probes))
    succeeded = all(check.status == "succeeded" for check in group_checks) and all(
        check.status == "succeeded" for check in query_checks
    )
    return VerificationReport(
        status="succeeded" if succeeded else "failed",
        groups=tuple(group_checks),
        queries=tuple(query_checks),
    )
