from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.ingestion.adapters import parse_generic_findings
from app.pipeline import TriagePipeline


def main() -> None:
    parser = argparse.ArgumentParser(description="Run vulnerability triage pipeline on a JSON file.")
    parser.add_argument("--input", "-i", required=True, help="Path to input JSON array of findings")
    parser.add_argument("--output", "-o", default=None, help="Optional output JSON path")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    args = parser.parse_args()

    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    findings = parse_generic_findings(payload)
    pipeline = TriagePipeline()
    results = pipeline.process_many(findings)

    output = [result.model_dump(mode="json") for result in results]
    json_text = json.dumps(output, indent=2 if args.pretty else None, ensure_ascii=False)

    if args.output:
        Path(args.output).write_text(json_text, encoding="utf-8")
        print(f"Saved results to {args.output}")
    else:
        print(json_text)


if __name__ == "__main__":
    main()
