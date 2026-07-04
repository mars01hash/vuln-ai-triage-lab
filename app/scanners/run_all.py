from __future__ import annotations

import argparse
from pathlib import Path

from app.scanners.common import read_json, write_json
from app.scanners.dependency_check_adapter import parse_dependency_check_results
from app.scanners.semgrep_adapter import parse_semgrep_results
from app.scanners.zap_adapter import parse_zap_results


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline scanner fixture aggregation for v4 demo.")
    parser.add_argument("--output", default="output/scanner_findings_all.json", help="Combined canonical findings JSON")
    parser.add_argument("--asset", default="demo-vulnerable-app")
    args = parser.parse_args()

    semgrep = parse_semgrep_results(read_json("data/scanner_fixtures/semgrep_results.json"), asset=args.asset)
    zap = parse_zap_results(read_json("data/scanner_fixtures/zap_report.json"), asset=args.asset)
    dep = parse_dependency_check_results(read_json("data/scanner_fixtures/dependency_check_report.json"), asset=args.asset)
    findings = semgrep + zap + dep
    write_json(args.output, [finding.model_dump(mode="json") for finding in findings])
    print(f"Combined scanner findings={len(findings)}; saved={args.output}")


if __name__ == "__main__":
    main()
