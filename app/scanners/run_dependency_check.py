from __future__ import annotations

import argparse
from pathlib import Path

from app.scanners.common import read_json, run_command, tool_available, write_json
from app.scanners.dependency_check_adapter import parse_dependency_check_results

FIXTURE = Path("data/scanner_fixtures/dependency_check_report.json")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Dependency-Check or parse bundled fixture into canonical findings.")
    parser.add_argument("--target", default="demo-vulnerable-app", help="Project directory to scan when dependency-check is installed")
    parser.add_argument("--raw-output-dir", default="output/dependency-check", help="Native Dependency-Check output directory")
    parser.add_argument("--output", default="output/dependency_check_findings.json", help="Canonical findings output JSON")
    parser.add_argument("--asset", default="demo-vulnerable-app", help="Asset name for canonical findings")
    parser.add_argument("--sample", action="store_true", help="Use bundled fixture instead of invoking dependency-check")
    args = parser.parse_args()

    if args.sample or not tool_available("dependency-check"):
        payload = read_json(FIXTURE)
        mode = "fixture"
    else:
        out_dir = Path(args.raw_output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        cmd = ["dependency-check", "--project", args.asset, "--scan", args.target, "--format", "JSON", "--out", str(out_dir)]
        proc = run_command(cmd, timeout=1200)
        raw_path = out_dir / "dependency-check-report.json"
        if not raw_path.exists():
            raise SystemExit(f"Dependency-Check did not produce JSON.\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
        payload = read_json(raw_path)
        mode = "dependency-check"

    findings = parse_dependency_check_results(payload, asset=args.asset)
    write_json(args.output, [finding.model_dump(mode="json") for finding in findings])
    print(f"Dependency-Check adapter mode={mode}; findings={len(findings)}; saved={args.output}")


if __name__ == "__main__":
    main()
