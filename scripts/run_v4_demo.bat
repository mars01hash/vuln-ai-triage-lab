@echo off
python -m app.ml.train_cwe_classifier --input data/cwe_training_findings.jsonl --output models/cwe_tfidf_logreg.joblib --metrics output/cwe_training_metrics.json
python -m app.scanners.run_all --output output/scanner_findings_all.json
python -m app.cli --input output/scanner_findings_all.json --use-ml --memory-backend sqlite --memory-file output/v4_memory.sqlite --output output/v4_results.json --report output/v4_report.md --pretty
python -m app.evaluation.full_benchmark --use-ml --output output/full_benchmark_metrics.json --report output/full_benchmark_report.md
