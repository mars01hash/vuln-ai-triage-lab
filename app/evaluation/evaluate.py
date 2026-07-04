from __future__ import annotations

import json
from pathlib import Path

from app.ingestion.adapters import parse_generic_findings
from app.pipeline import TriagePipeline


def evaluate_cwe_accuracy(input_path: str) -> dict[str, float | int]:
    payload = json.loads(Path(input_path).read_text(encoding="utf-8"))
    expected_by_id = {str(item.get("finding_id") or item.get("id")): item.get("expected_cwe") for item in payload if item.get("expected_cwe")}
    findings = parse_generic_findings(payload)
    labeled = [f for f in findings if f.finding_id in expected_by_id]
    if not labeled:
        return {"count": 0, "accuracy": 0.0}

    pipeline = TriagePipeline()
    results = pipeline.process_many(findings)
    by_id = {result.finding_id: result for result in results}
    correct = sum(1 for finding in labeled if by_id[finding.finding_id].canonical_cwe == expected_by_id[finding.finding_id])
    return {"count": len(labeled), "correct": correct, "accuracy": round(correct / len(labeled), 3)}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="data/eval_labeled_findings.json")
    args = parser.parse_args()
    print(json.dumps(evaluate_cwe_accuracy(args.input), indent=2))
