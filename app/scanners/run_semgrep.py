from __future__ import annotations

import argparse
from pathlib import Path

from app.scanners.common import read_json, run_command, tool_available, write_json
from app.scanners.semgrep_adapter import findings_to_json, parse_semgrep_results

FIXTURE = Path("data/scanner_fixtures/semgrep_results.json")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Semgrep or parse bundled Semgrep fixture into canonical findings.")
    parser.add_argument("--target", default="demo-vulnerable-app", help="Code directory to scan when Semgrep is installed")
    parser.add_argument("--raw-output", default="output/semgrep_raw.json", help="Where native Semgrep JSON should be stored")
    parser.add_argument("--output", default="output/semgrep_findings.json", help="Canonical findings output JSON")
    parser.add_argument("--asset", default="demo-vulnerable-app", help="Asset name for canonical findings")
    parser.add_argument("--sample", action="store_true", help="Use bundled fixture instead of invoking Semgrep")
    args = parser.parse_args()

    raw_path = Path(args.raw_output)
    if args.sample or not tool_available("semgrep"):
        payload = read_json(FIXTURE)
        mode = "fixture"
    else:
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        cmd = ["semgrep", "scan", "--config", "p/owasp-top-ten", "--json", "--output", str(raw_path), args.target]
        proc = run_command(cmd, timeout=600)
        if proc.returncode not in {0, 1}:  # Semgrep may return 1 when findings exist depending config/version.
            raise SystemExit(f"Semgrep failed.\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
        payload = read_json(raw_path)
        mode = "semgrep"

    findings = parse_semgrep_results(payload, asset=args.asset)
    write_json(args.output, findings_to_json(findings))
    print(f"Semgrep adapter mode={mode}; findings={len(findings)}; saved={args.output}")


if __name__ == "__main__":
    main()
