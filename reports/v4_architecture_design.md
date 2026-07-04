# v4 Architecture Design

v4 upgrades the project from a model-centric prototype into a portfolio-ready AppSec AI workflow.

## Main Design Change

v3 accepted canonical/sample vulnerability findings. v4 adds a scanner integration layer so the same pipeline can consume native-style outputs from SAST, DAST, and SCA tools.

```text
Semgrep / OWASP ZAP / Dependency-Check
        ↓
Scanner adapters
        ↓
Canonical VulnerabilityFinding schema
        ↓
CWE normalization
        ↓
Memory-based deduplication
        ↓
Reachability gate
        ↓
Bayesian-style priority scoring
        ↓
LLM/local triage agent
        ↓
WAF policy gate + human approval
        ↓
Dashboard, reports, benchmark metrics
```

## Why Scanner Adapters Exist

Real AppSec tools use inconsistent schemas. Semgrep reports code locations, ZAP reports runtime alerts and parameters, and Dependency-Check reports dependency/CVE records. The adapters isolate this schema noise from the ML pipeline.

## Why the Demo Vulnerable App Exists

The demo app gives the project an end-to-end story: scan a target, ingest scanner results, normalize findings, score risk, and produce human-reviewable triage. It contains intentionally vulnerable examples for SQL injection, XSS, path traversal, hard-coded secret, and dependency risk.

## Why Fixtures Are Included

Not every machine has Semgrep, ZAP, or Dependency-Check installed. The project therefore includes bundled scanner fixtures. This preserves repeatability and makes the project runnable immediately while still demonstrating how real scanner outputs are handled.

## Why Dashboard Was Added

Security triage is an operational workflow. A dashboard makes it easier to show risk distribution, highest-priority findings, duplicate groups, WAF proposal status, and human-review decisions.

## Why Benchmark Was Added

The role requires evaluation discipline. v4 adds a full benchmark command that reports CWE accuracy, macro-F1, rank accuracy, WAF false positive rate, and schema validity proxy.
