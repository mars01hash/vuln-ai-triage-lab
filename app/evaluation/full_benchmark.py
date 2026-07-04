from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from sklearn.metrics import accuracy_score, f1_score

from app.ingestion.adapters import parse_generic_findings
from app.pipeline import TriagePipeline
from app.reporting.report_writer import write_markdown_report
from app.scanners.common import read_json, write_json
from app.scanners.dependency_check_adapter import parse_dependency_check_results
from app.scanners.semgrep_adapter import parse_semgrep_results
from app.scanners.zap_adapter import parse_zap_results
from app.storage.sqlite_vector_memory import SqliteVulnerabilityMemory

RISK_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _build_fixture_findings(asset: str) -> list[dict]:
    findings = []
    findings.extend(parse_semgrep_results(read_json("data/scanner_fixtures/semgrep_results.json"), asset=asset))
    findings.extend(parse_zap_results(read_json("data/scanner_fixtures/zap_report.json"), asset=asset))
    findings.extend(parse_dependency_check_results(read_json("data/scanner_fixtures/dependency_check_report.json"), asset=asset))
    return [finding.model_dump(mode="json") for finding in findings]


def _safe_f1(y_true: list[str], y_pred: list[str]) -> float:
    labels = sorted(set(y_true) | set(y_pred))
    return float(f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0))


def run_benchmark(use_ml: bool, output: str, report: str, asset: str = "demo-vulnerable-app") -> dict:
    canonical_payload = _build_fixture_findings(asset)
    expectations = {item["finding_id"]: item for item in read_json("data/full_benchmark_expected.json")}

    memory_path = Path("output/full_benchmark_memory.sqlite")
    if memory_path.exists():
        memory_path.unlink()
    memory = SqliteVulnerabilityMemory(db_path=memory_path, similarity_threshold=0.72)
    pipeline = TriagePipeline(memory=memory, use_ml_classifier=use_ml, memory_backend_name="sqlite_vector_memory")
    results = pipeline.process_many(parse_generic_findings(canonical_payload))

    y_true: list[str] = []
    y_pred: list[str] = []
    rank_hits = 0
    waf_total = 0
    waf_false_positive = 0
    schema_valid = 0

    errors: list[dict] = []
    for result in results:
        exp = expectations.get(result.finding_id)
        if not exp:
            continue
        y_true.append(exp["expected_cwe"])
        y_pred.append(result.canonical_cwe)
        if result.canonical_cwe != exp["expected_cwe"]:
            errors.append({"finding_id": result.finding_id, "type": "cwe", "expected": exp["expected_cwe"], "actual": result.canonical_cwe})
        expected_min = RISK_ORDER[exp["expected_min_rank"]]
        if RISK_ORDER.get(result.risk_level, 0) >= expected_min:
            rank_hits += 1
        else:
            errors.append({"finding_id": result.finding_id, "type": "rank", "expected_min": exp["expected_min_rank"], "actual": result.risk_level})
        waf_total += 1
        if result.waf_rule_allowed and not exp["expected_waf_allowed"]:
            waf_false_positive += 1
            errors.append({"finding_id": result.finding_id, "type": "waf_false_positive", "actual": True})
        if result.finding_id and result.canonical_cwe and result.reasoning_summary and result.recommended_fix:
            schema_valid += 1

    duplicate_count = sum(1 for result in results if result.duplicate_of)
    source_counts = Counter(result.source_type.value for result in results)

    metrics = {
        "mode": "ml" if use_ml else "rules",
        "total_findings": len(results),
        "source_counts": dict(source_counts),
        "cwe_accuracy": round(float(accuracy_score(y_true, y_pred)), 4) if y_true else 0.0,
        "cwe_macro_f1": round(_safe_f1(y_true, y_pred), 4) if y_true else 0.0,
        "priority_rank_accuracy": round(rank_hits / len(y_true), 4) if y_true else 0.0,
        "waf_false_positive_rate": round(waf_false_positive / waf_total, 4) if waf_total else 0.0,
        "llm_json_validity_proxy": round(schema_valid / len(results), 4) if results else 0.0,
        "deduplication_groups_detected": duplicate_count,
        "errors": errors,
    }

    write_json(output, metrics)
    write_markdown_report(results, report)
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Run v4 full benchmark over scanner fixture findings.")
    parser.add_argument("--use-ml", action="store_true", help="Use trained ML CWE classifier")
    parser.add_argument("--output", default="output/full_benchmark_metrics.json", help="Metrics JSON path")
    parser.add_argument("--report", default="output/full_benchmark_report.md", help="Detailed triage Markdown report path")
    parser.add_argument("--asset", default="demo-vulnerable-app")
    args = parser.parse_args()
    metrics = run_benchmark(args.use_ml, args.output, args.report, args.asset)
    print(json.dumps(metrics, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
