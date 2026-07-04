# Scanners Integration Module

This component ingests raw, tool-specific output formats from SAST, DAST, and SCA scanners and parses them into the canonical `VulnerabilityFinding` schema.

## Files
* `semgrep_adapter.py`: Adapter to parse Semgrep JSON output.
* `zap_adapter.py`: Adapter to parse OWASP ZAP dynamic scans.
* `dependency_check_adapter.py`: Adapter to parse Dependency-Check SCA findings.
* `common.py`: Shared subprocess execution utilities and CVSS/CWE mapping logic.
* `run_semgrep.py` / `run_zap.py` / `run_dependency_check.py`: Execution runners to trigger tool scans locally (using command-line invocations) or load saved mock fixtures.
* `run_all.py`: Combines and consolidates raw fixtures into a single canonical payload.

## Python Usage
```python
from app.scanners.semgrep_adapter import parse_semgrep_results
from app.scanners.common import read_json

# Parses raw Semgrep output to canonical findings
findings = parse_semgrep_results(read_json("data/scanner_fixtures/semgrep_results.json"))
print(f"Parsed {len(findings)} findings from Semgrep.")
```

## Why it works
Different security tools output findings using highly inconsistent schemas. By writing dedicated adapters for Semgrep, ZAP, and Dependency-Check, we decouple scanner-specific noise from the core classification, prioritization, and gating pipeline.
