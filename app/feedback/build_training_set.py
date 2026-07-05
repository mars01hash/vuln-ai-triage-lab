from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    rows = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def _write_jsonl(path: str | Path, rows: list[dict[str, Any]]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n", encoding="utf-8")


def build_training_set_from_feedback(
    base_training_path: str | Path,
    results_path: str | Path,
    feedback_path: str | Path,
    output_path: str | Path,
) -> dict[str, Any]:
    base_rows = _read_jsonl(base_training_path)
    results = json.loads(Path(results_path).read_text(encoding="utf-8")) if Path(results_path).exists() else []
    feedback_rows = _read_jsonl(feedback_path)

    result_by_id = {item.get("finding_id"): item for item in results}
    generated_rows: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []

    for feedback in feedback_rows:
        corrected_cwe = feedback.get("corrected_cwe")
        finding_id = feedback.get("finding_id")
        if not corrected_cwe or not finding_id:
            skipped.append({"finding_id": str(finding_id), "reason": "missing corrected_cwe or finding_id"})
            continue
        result = result_by_id.get(finding_id)
        if not result:
            skipped.append({"finding_id": str(finding_id), "reason": "finding not present in results file"})
            continue
        text = " ".join(
            str(part)
            for part in [
                result.get("title", ""),
                result.get("description", ""),
                result.get("canonical_cwe", ""),
                result.get("reasoning_summary", ""),
                result.get("recommended_fix", ""),
            ]
            if part
        ).strip()
        if not text:
            skipped.append({"finding_id": str(finding_id), "reason": "empty training text"})
            continue
        generated_rows.append({"text": text, "cwe": corrected_cwe, "source": "human_feedback", "finding_id": finding_id})

    merged = base_rows + generated_rows
    _write_jsonl(output_path, merged)
    return {
        "base_rows": len(base_rows),
        "feedback_rows_seen": len(feedback_rows),
        "feedback_rows_added": len(generated_rows),
        "skipped": skipped,
        "output_rows": len(merged),
        "output_path": str(output_path),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build an augmented CWE training JSONL from human feedback and prior triage results.")
    parser.add_argument("--base", default="data/cwe_training_findings.jsonl")
    parser.add_argument("--results", default="output/v5_results_ml.json")
    parser.add_argument("--feedback", default="output/api_human_feedback.jsonl")
    parser.add_argument("--output", default="output/cwe_training_augmented_from_feedback.jsonl")
    args = parser.parse_args()
    summary = build_training_set_from_feedback(args.base, args.results, args.feedback, args.output)
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
