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
