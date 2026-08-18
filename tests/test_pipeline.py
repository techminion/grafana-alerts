from pathlib import Path


def test_pipeline_requires_separate_prune_plan_and_delete_gates() -> None:
    pipeline = Path("azure-pipelines.yml").read_text(encoding="utf-8")

    assert "PRUNE_PLAN_ENABLED" in pipeline
    assert "PRUNE_ENABLED" in pipeline
    assert "--prune-plan" in pipeline
    assert '--confirm-prune "DELETE ALLOWLISTED GROUPS"' in pipeline
    assert "artifact: grafana-plan" in pipeline
