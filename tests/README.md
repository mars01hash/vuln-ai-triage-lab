# Tests Directory

This directory contains automated unit and regression tests for the triage pipeline.

## Files
* `test_pipeline.py`: Tests mapping logic, reachability gating, and WAF proposal safety gates.

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

## Why it works
Automated validation is the only way to guarantee that modifications to classifiers or scoring models do not bypass hard-coded safety gates, protecting production systems from accidental deployments.
