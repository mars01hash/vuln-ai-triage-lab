from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.evaluation.full_benchmark import run_benchmark
from app.evaluation.model_calibration import run_calibration
from app.scanners.common import write_json


def run_v5_benchmark(
    use_ml: bool,
    output: str,
    report: str,
    calibration_output: str,
    calibration_report: str,
) -> dict:
    benchmark_metrics = run_benchmark(
        use_ml=use_ml,
        output=output,
        report=report,
        asset="demo-vulnerable-app",
    )
    calibration_metrics = None
    if use_ml:
        calibration_metrics = run_calibration(
            input_path="data/sample_findings_all.json",
            labels_path="data/eval_labeled_findings.json",
            model_path="models/cwe_tfidf_logreg.joblib",
            output=calibration_output,
            report=calibration_report,
            bins=5,
        )
    combined = {
        "v5_summary": {
            "benchmark_mode": "ml" if use_ml else "rules",
            "production_readiness_note": "Small offline fixtures only. Replace with historical scanner data before claiming production performance.",
        },
        "triage_benchmark": benchmark_metrics,
        "cwe_calibration": calibration_metrics,
    }
    combined_path = Path(output).with_name("v5_combined_benchmark.json")
    write_json(combined_path, combined)
    return combined


def main() -> None:
    parser = argparse.ArgumentParser(description="Run v5 benchmark: triage metrics + optional ML calibration metrics.")
    parser.add_argument("--use-ml", action="store_true")
    parser.add_argument("--output", default="output/v5_full_benchmark_metrics.json")
    parser.add_argument("--report", default="output/v5_full_benchmark_report.md")
    parser.add_argument("--calibration-output", default="output/v5_cwe_calibration_metrics.json")
    parser.add_argument("--calibration-report", default="output/v5_cwe_calibration_report.md")
    args = parser.parse_args()
    result = run_v5_benchmark(args.use_ml, args.output, args.report, args.calibration_output, args.calibration_report)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
