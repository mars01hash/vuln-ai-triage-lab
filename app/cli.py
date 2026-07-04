from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.ingestion.adapters import parse_generic_findings
from app.pipeline import TriagePipeline
from app.reporting.report_writer import write_markdown_report
from app.storage.memory_store import VulnerabilityMemory


def main() -> None:
    parser = argparse.ArgumentParser(description="Run vulnerability triage pipeline on a JSON file.")
    parser.add_argument("--input", "-i", required=True, help="Path to input JSON array of findings")
    parser.add_argument("--output", "-o", default=None, help="Optional output JSON path")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    parser.add_argument("--use-ml", action="store_true", help="Use trained scikit-learn CWE classifier instead of rule classifier")
    parser.add_argument("--model-path", default="models/cwe_tfidf_logreg.joblib", help="Path to trained ML model")
    parser.add_argument("--memory-file", default=None, help="Optional JSON file for persistent vulnerability memory")
    parser.add_argument("--report", default=None, help="Optional Markdown batch report path")
    args = parser.parse_args()

    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    findings = parse_generic_findings(payload)
    memory = VulnerabilityMemory(memory_path=args.memory_file) if args.memory_file else VulnerabilityMemory()
    pipeline = TriagePipeline(memory=memory, use_ml_classifier=args.use_ml, model_path=args.model_path)
    results = pipeline.process_many(findings)

    output = [result.model_dump(mode="json") for result in results]
    json_text = json.dumps(output, indent=2 if args.pretty else None, ensure_ascii=False)

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(json_text, encoding="utf-8")
        print(f"Saved results to {args.output}")
    else:
        print(json_text)

    if args.report:
        write_markdown_report(results, args.report)
        print(f"Saved Markdown report to {args.report}")


if __name__ == "__main__":
    main()
