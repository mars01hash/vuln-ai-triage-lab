#!/usr/bin/env bash
set -e
python -m app.ml.train_cwe_classifier --input data/cwe_training_findings.jsonl --output models/cwe_tfidf_logreg.joblib --metrics output/cwe_training_metrics.json
python -m app.cli --input data/sample_findings_all.json --use-ml --memory-backend sqlite --memory-file output/v3_memory.sqlite --output output/v3_results.json --report output/v3_report.md --pretty
