# Tests Directory

This directory contains automated unit and regression tests for the triage pipeline.

## Files
* `test_pipeline.py`: Tests mapping logic, reachability gating, vector memory, LLM fallback, and WAF proposal safety gates.
* `test_v4_scanners.py`: Tests the Semgrep, ZAP, and Dependency-Check adapters, pipeline integration, and benchmark calculation execution.

## Running Tests
Run pytest from the root project directory:
```bash
pytest
```

## Coverage Cases
The test suite ensures:
1. **CWE Mapping correctness:** Checks that keywords correctly resolve to the standard CWE-89 class.
2. **SAST-Only Isolation:** Asserts that SAST inputs are blocked from generating WAF patch proposals to prevent blocking rules.
3. **DAST WAF Rules Generation:** Asserts that confirmed reachable, high-priority dynamic findings can successfully propose virtual patches with human approval markers.
4. **SQLite Persistent Memory Deduplication:** Verifies that the SQLite database correctly matches and groups similar findings, logging duplicates successfully.
5. **OpenAI Agent Error Fallback:** Deliberately deletes the `OPENAI_API_KEY` env variable to verify that the optional LLM agent falls back gracefully to the deterministic local rule engine without throwing uncaught exceptions.
6. **Multi-Scanner Parsing Correctness:** Verifies that raw Semgrep, ZAP, and Dependency-Check adapter codes extract correct properties (severity, package, etc.) into the canonical schema.
7. **Full Benchmark Verification:** Runs the mock benchmark script to ensure metrics evaluate without raising errors.

## Why it works
Automated validation is the only way to guarantee that modifications to classifiers, databases, or scoring models do not bypass hard-coded safety gates, protecting production systems from accidental deployments.
