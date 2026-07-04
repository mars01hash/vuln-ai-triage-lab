from __future__ import annotations

import json
from pathlib import Path

from app.ingestion.adapters import parse_generic_findings
from app.pipeline import TriagePipeline


def evaluate_cwe_accuracy(input_path: str, use_ml: bool = False, model_path: str = "models/cwe_tfidf_logreg.joblib") -> dict[str, float | int | str]:
    payload = json.loads(Path(input_path).read_text(encoding="utf-8"))
    expected_by_id = {
        str(item.get("finding_id") or item.get("id")): item.get("expected_cwe")
        for item in payload
        if item.get("expected_cwe")
    }
    findings = parse_generic_findings(payload)
    labeled = [f for f in findings if f.finding_id in expected_by_id]
    if not labeled:
        return {"count": 0, "accuracy": 0.0, "mode": "ml" if use_ml else "rules"}

    pipeline = TriagePipeline(use_ml_classifier=use_ml, model_path=model_path)
    results = pipeline.process_many(findings)
    by_id = {result.finding_id: result for result in results}
    correct = sum(
        1
        for finding in labeled
        if by_id[finding.finding_id].canonical_cwe == expected_by_id[finding.finding_id]
    )
    errors = [
        {
            "finding_id": finding.finding_id,
            "expected": expected_by_id[finding.finding_id],
            "predicted": by_id[finding.finding_id].canonical_cwe,
        }
        for finding in labeled
        if by_id[finding.finding_id].canonical_cwe != expected_by_id[finding.finding_id]
    ]
    return {
        "mode": "ml" if use_ml else "rules",
        "count": len(labeled),
        "correct": correct,
        "accuracy": round(correct / len(labeled), 3),
        "errors": errors,
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="data/eval_labeled_findings.json")
    parser.add_argument("--use-ml", action="store_true")
    parser.add_argument("--model-path", default="models/cwe_tfidf_logreg.joblib")
    args = parser.parse_args()
    print(json.dumps(evaluate_cwe_accuracy(args.input, args.use_ml, args.model_path), indent=2))
