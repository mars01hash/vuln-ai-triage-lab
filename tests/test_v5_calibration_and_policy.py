from __future__ import annotations

import json
from pathlib import Path

from app.evaluation.model_calibration import run_calibration
from app.ingestion.adapters import parse_generic_findings
from app.pipeline import TriagePipeline
from app.scanners.common import read_json
from app.storage.sqlite_vector_memory import SqliteVulnerabilityMemory
from app.threat_intel.enrichment import enrich_finding_with_threat_intel


def test_threat_intel_enrichment_sets_exploit_signal():
    finding = parse_generic_findings(read_json("data/sample_findings_all.json"))[0]
    signal = enrich_finding_with_threat_intel(finding, "CWE-89")
    assert signal["exploit_likelihood"] >= 0.85
    assert finding.exploit_available is True
    assert "threat_intel" in finding.raw


def test_callgraph_reachability_in_pipeline(tmp_path: Path):
    finding = parse_generic_findings([
        {
            "finding_id": "V5-CALLGRAPH-001",
            "source_type": "SAST",
            "tool_name": "Semgrep",
            "title": "SQL injection in orders endpoint",
            "description": "User input reaches SQL query in orders endpoint",
            "cvss": 8.8,
            "asset": "demo-vulnerable-app",
            "endpoint": "/api/orders",
            "file_path": "demo-vulnerable-app/app.py",
            "business_criticality": "high",
            "asset_exposure": "internet"
        }
    ])[0]
    memory = SqliteVulnerabilityMemory(db_path=tmp_path / "mem.sqlite")
    result = TriagePipeline(memory=memory).process_one(finding)
    assert result.reachable is True
    assert "Callgraph" in result.reachability_reason


def test_calibration_cli_function_outputs_metrics(tmp_path: Path):
    # Model is trained in test setup command for release validation; this test
    # verifies the calibration function returns the expected fields.
    metrics_path = tmp_path / "calibration.json"
    report_path = tmp_path / "calibration.md"
    metrics = run_calibration(
        input_path="data/sample_findings_all.json",
        labels_path="data/eval_labeled_findings.json",
        model_path="models/cwe_tfidf_logreg.joblib",
        output=str(metrics_path),
        report=str(report_path),
        bins=5,
    )
    assert metrics_path.exists()
    assert report_path.exists()
    assert "expected_calibration_error" in metrics
    assert "brier_score_multiclass" in metrics
    assert isinstance(metrics["reliability_bins"], list)


def test_sentence_transformer_encoder_serialization(tmp_path: Path):
    import sys
    from unittest.mock import MagicMock
    from sklearn.linear_model import LogisticRegression

    from app.ml.cwe_ml_classifier import SentenceTransformerEncoder

    # Mock sentence_transformers library
    mock_model = MagicMock()
    mock_model.encode.return_value = [[0.1, 0.2, 0.3], [0.4, 0.5, 0.6]]
    mock_st_class = MagicMock(return_value=mock_model)

    mock_module = MagicMock()
    mock_module.SentenceTransformer = mock_st_class
    sys.modules["sentence_transformers"] = mock_module

    try:
        encoder = SentenceTransformerEncoder(model_name="mock-model")
        X = ["text one", "text two"]
        encoder.fit(X)
        res = encoder.transform(X)

        assert len(res) == 2
        assert len(res[0]) == 3
        mock_st_class.assert_called_once_with("mock-model")
        mock_model.encode.assert_called_once_with(X, show_progress_bar=False, normalize_embeddings=True)

        from sklearn.pipeline import Pipeline
        pipe = Pipeline([
            ("encoder", encoder),
            ("clf", LogisticRegression())
        ])
        pipe.fit(X, [0, 1])

        # Verify joblib serialization
        model_path = tmp_path / "mock_model.joblib"
        import joblib
        joblib.dump(pipe, model_path)

        # Check that file size is small (no heavy weights serialized)
        assert model_path.stat().st_size < 50 * 1024

        # Reload pipeline
        reloaded_pipe = joblib.load(model_path)
        reloaded_encoder = reloaded_pipe.named_steps["encoder"]
        assert reloaded_encoder.model is None

        # Predict triggers lazy loading transform
        reloaded_res = reloaded_pipe.predict(X)
        assert len(reloaded_res) == 2
    finally:
        if "sentence_transformers" in sys.modules:
            del sys.modules["sentence_transformers"]


def test_train_classifier_logs_to_mlflow(tmp_path: Path):
    import sys
    from unittest.mock import MagicMock
    from app.ml.train_cwe_classifier import train_classifier

    mock_mlflow = MagicMock()
    mock_mlflow.active_run.return_value = None
    sys.modules["mlflow"] = mock_mlflow

    try:
        model_path = tmp_path / "model.joblib"
        metrics_path = tmp_path / "metrics.json"

        train_classifier(
            input_path="data/cwe_training_findings.jsonl",
            output_path=model_path,
            metrics_path=metrics_path,
            use_mlflow=True,
            encoder="tfidf",
            mlflow_experiment="Test_Experiment"
        )

        mock_mlflow.set_experiment.assert_called_once_with("Test_Experiment")
        mock_mlflow.start_run.assert_called_once()
        mock_mlflow.log_param.assert_any_call("encoder_type", "tfidf")
        mock_mlflow.log_metric.assert_any_call("accuracy", 1.0)
        mock_mlflow.log_artifact.assert_called_once_with(str(model_path))
    finally:
        if "mlflow" in sys.modules:
            del sys.modules["mlflow"]
