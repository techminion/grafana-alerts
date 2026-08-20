from pathlib import Path


def test_pipeline_requires_separate_prune_plan_and_delete_gates() -> None:
    pipeline = Path("azure-pipelines.yml").read_text(encoding="utf-8")

    assert "PRUNE_PLAN_ENABLED" in pipeline
    assert "PRUNE_ENABLED" in pipeline
    assert "--prune-plan" in pipeline
    assert '--confirm-prune "DELETE ALLOWLISTED GROUPS"' in pipeline
    assert "artifact: grafana-plan" in pipeline


def test_pipeline_always_publishes_deployment_receipt() -> None:
    pipeline = Path("azure-pipelines.yml").read_text(encoding="utf-8")

    assert pipeline.count("--receipt") == 3
    assert "artifact: deployment-receipt" in pipeline
    assert "condition: always()" in pipeline


def test_pipeline_requires_explicit_audited_rollback_inputs() -> None:
    pipeline = Path("azure-pipelines.yml").read_text(encoding="utf-8")

    assert "rollbackBuildId" in pipeline
    assert "rollbackReason" in pipeline
    assert "DownloadPipelineArtifact@2" in pipeline
    assert "grafana-alerts rollback-plan" in pipeline
    assert "artifact: grafana-rollback-plan" in pipeline
    assert "artifact: rollback-source-receipt" in pipeline
    assert '--confirm-rollback "ROLL BACK REVIEWED ARTIFACT"' in pipeline
    assert 'ROLLBACK_ENABLED: "true"' in pipeline


def test_pipeline_post_verifies_every_mutating_path() -> None:
    pipeline = Path("azure-pipelines.yml").read_text(encoding="utf-8")

    assert pipeline.count("--verification-attempts 5") == 3
    assert pipeline.count("--verification-delay 2") == 3
    assert pipeline.count("--query-attempts 1") == 3
    assert pipeline.count("--query-workers 8") == 3
    assert pipeline.count("post-verify") == 3


def test_pipeline_routes_every_mutation_through_proxy() -> None:
    pipeline = Path("azure-pipelines.yml").read_text(encoding="utf-8")

    assert pipeline.count("ALERT_PROXY_URL: $(ALERT_PROXY_URL)") == 3
    assert pipeline.count("ALERT_ATTESTATION_KEY: $(ALERT_ATTESTATION_KEY)") == 3


def test_pipeline_has_opt_in_read_only_drift_stage() -> None:
    pipeline = Path("azure-pipelines.yml").read_text(encoding="utf-8")

    assert "stage: Drift" in pipeline
    assert "DRIFT_ENABLED" in pipeline
    assert "grafana-alerts drift" in pipeline
    assert "--fail-on-drift" in pipeline
    assert "artifact: grafana-drift-report" in pipeline
    assert "ne(variables['Build.Reason'], 'Schedule')" in pipeline
