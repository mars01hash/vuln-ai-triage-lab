#!/usr/bin/env bash
set -euo pipefail
python -m app.ml.train_cwe_classifier --input data/cwe_training_findings.jsonl --output models/cwe_tfidf_logreg.joblib --metrics output/cwe_training_metrics.json
python -m app.scanners.run_all --output output/scanner_findings_all.json
python -m app.cli --input output/scanner_findings_all.json --use-ml --memory-backend sqlite --memory-file output/v5_memory.sqlite --output output/v5_results_ml.json --report output/v5_report_ml.md --audit-log output/v5_audit_log.jsonl --pretty
python -m app.evaluation.model_calibration --input data/sample_findings_all.json --labels data/eval_labeled_findings.json --output output/v5_cwe_calibration_metrics.json --report output/v5_cwe_calibration_report.md
python -m app.evaluation.full_benchmark_v5 --use-ml --output output/v5_full_benchmark_metrics.json --report output/v5_full_benchmark_report.md
