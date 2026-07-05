from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.ingestion.adapters import parse_generic_findings
from app.ml.calibration import evaluate_cwe_calibration
from app.ml.cwe_ml_classifier import MLCWEClassifier
from app.scanners.common import read_json, write_json


def _write_markdown(result: dict, output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# CWE Classifier Calibration Report",
        "",
        "## Summary",
        "",
        f"- Accuracy: **{result['accuracy']}**",
        f"- Macro F1: **{result['macro_f1']}**",
        f"- Multiclass Brier score: **{result['brier_score_multiclass']}**",
        f"- Expected Calibration Error: **{result['expected_calibration_error']}**",
        f"- Mean confidence: **{result['mean_confidence']}**",
        "",
        "## Reliability Bins",
        "",
        "| Confidence Bin | Count | Accuracy | Mean Confidence | Gap |",
        "|---|---:|---:|---:|---:|",
    ]
    for item in result["reliability_bins"]:
        lines.append(
            f"| {item['bin_low']}-{item['bin_high']} | {item['count']} | {item['accuracy']} | {item['confidence']} | {item['gap']} |"
        )
    lines.extend([
        "",
        "## Example Predictions",
        "",
        "| Finding | Expected | Predicted | Confidence | Correct |",
        "|---|---|---|---:|---|",
    ])
    for ex in result["examples"]:
        lines.append(f"| {ex['finding_id']} | {ex['expected_cwe']} | {ex['predicted_cwe']} | {ex['confidence']} | {ex['correct']} |")
    lines.extend([
        "",
        "## How to interpret this",
        "",
        "A calibrated model should not only rank findings correctly; its confidence should be meaningful. For example, findings predicted with about 0.80 confidence should be correct about 80% of the time over a sufficiently large validation set.",
        "",
        "The bundled dataset is intentionally small for demonstration. Replace it with historical labeled scanner findings before using these metrics as real evidence.",
    ])
    path.write_text("\n".join(lines), encoding="utf-8")


def run_calibration(input_path: str, labels_path: str, model_path: str, output: str, report: str, bins: int) -> dict:
    payload = read_json(input_path)
    findings = parse_generic_findings(payload)
    labels = {item["finding_id"]: item["expected_cwe"] for item in read_json(labels_path)}
    classifier = MLCWEClassifier.load(model_path)
    result = evaluate_cwe_calibration(classifier, findings, labels, n_bins=bins)
    result_dict = result.__dict__
    write_json(output, result_dict)
    _write_markdown(result_dict, report)
    return result_dict


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate CWE classifier calibration, confidence, Brier score, and ECE.")
    parser.add_argument("--input", default="data/sample_findings_all.json")
    parser.add_argument("--labels", default="data/eval_labeled_findings.json")
    parser.add_argument("--model-path", default="models/cwe_tfidf_logreg.joblib")
    parser.add_argument("--output", default="output/cwe_calibration_metrics.json")
    parser.add_argument("--report", default="output/cwe_calibration_report.md")
    parser.add_argument("--bins", type=int, default=5)
    args = parser.parse_args()
    result = run_calibration(args.input, args.labels, args.model_path, args.output, args.report, args.bins)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
