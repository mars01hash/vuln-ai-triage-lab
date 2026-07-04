from __future__ import annotations

import argparse
from pathlib import Path

from app.scanners.common import read_json, run_command, tool_available, write_json
from app.scanners.zap_adapter import parse_zap_results

FIXTURE = Path("data/scanner_fixtures/zap_report.json")


def _zap_available() -> bool:
    return tool_available("zap-baseline.py") or tool_available("docker")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run OWASP ZAP baseline or parse bundled ZAP fixture into canonical findings.")
    parser.add_argument("--target", default="http://localhost:5000", help="Running web app URL when ZAP is available")
    parser.add_argument("--raw-output", default="output/zap_raw.json", help="Where native ZAP JSON should be stored")
    parser.add_argument("--output", default="output/zap_findings.json", help="Canonical findings output JSON")
    parser.add_argument("--asset", default="demo-vulnerable-app", help="Asset name for canonical findings")
    parser.add_argument("--sample", action="store_true", help="Use bundled fixture instead of invoking ZAP")
    args = parser.parse_args()

    raw_path = Path(args.raw_output)
    if args.sample or not _zap_available():
        payload = read_json(FIXTURE)
        mode = "fixture"
    else:
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        if tool_available("zap-baseline.py"):
            cmd = ["zap-baseline.py", "-t", args.target, "-J", str(raw_path)]
        else:
            # Requires Docker network access to target; for local host you may need host.docker.internal.
            cmd = [
                "docker", "run", "--rm", "-v", f"{raw_path.parent.resolve()}:/zap/wrk:rw",
                "ghcr.io/zaproxy/zaproxy:stable", "zap-baseline.py", "-t", args.target, "-J", raw_path.name,
            ]
        proc = run_command(cmd, timeout=900)
        if not raw_path.exists():
            raise SystemExit(f"ZAP did not produce JSON.\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
        payload = read_json(raw_path)
        mode = "zap"

    findings = parse_zap_results(payload, asset=args.asset)
    write_json(args.output, [finding.model_dump(mode="json") for finding in findings])
    print(f"ZAP adapter mode={mode}; findings={len(findings)}; saved={args.output}")


if __name__ == "__main__":
    main()
