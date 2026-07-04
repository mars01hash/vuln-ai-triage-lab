from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.ingestion.adapters import parse_generic_findings
from app.pipeline import TriagePipeline
from app.reporting.report_writer import write_markdown_report
from app.storage.memory_store import VulnerabilityMemory
from app.storage.sqlite_vector_memory import SqliteVulnerabilityMemory


def build_memory(args: argparse.Namespace):
    if args.memory_backend == "sqlite":
        return SqliteVulnerabilityMemory(db_path=args.memory_file or "output/vulnerability_memory.sqlite"), "sqlite_vector_memory"
    if args.memory_backend == "json":
        return VulnerabilityMemory(memory_path=args.memory_file) if args.memory_file else VulnerabilityMemory(), "json_or_in_memory"
    raise ValueError(f"Unsupported memory backend: {args.memory_backend}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run vulnerability triage pipeline on a JSON file.")
    parser.add_argument("--input", "-i", required=True, help="Path to input JSON array of findings")
    parser.add_argument("--output", "-o", default=None, help="Optional output JSON path")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    parser.add_argument("--use-ml", action="store_true", help="Use trained scikit-learn CWE classifier instead of rule classifier")
    parser.add_argument("--model-path", default="models/cwe_tfidf_logreg.joblib", help="Path to trained ML model")
    parser.add_argument("--memory-backend", choices=["json", "sqlite"], default="sqlite", help="Persistent memory backend")
    parser.add_argument("--memory-file", default=None, help="JSON file or SQLite DB path for persistent vulnerability memory")
    parser.add_argument("--report", default=None, help="Optional Markdown batch report path")
    parser.add_argument("--use-llm", action="store_true", help="Use optional OpenAI LLM agent. Falls back locally if unavailable.")
    parser.add_argument("--llm-model", default="gpt-4o-mini", help="OpenAI model name for optional LLM triage")
    args = parser.parse_args()

    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    findings = parse_generic_findings(payload)
    memory, memory_backend_name = build_memory(args)
    pipeline = TriagePipeline(
        memory=memory,
        use_ml_classifier=args.use_ml,
        model_path=args.model_path,
        use_llm_agent=args.use_llm,
        llm_model=args.llm_model,
        memory_backend_name=memory_backend_name,
    )
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

    if hasattr(memory, "summary"):
        print("Memory summary:", json.dumps(memory.summary(), ensure_ascii=False))


if __name__ == "__main__":
    main()
