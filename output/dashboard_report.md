# Vulnerability AI Triage Batch Report

## Executive Summary

- Total findings processed: **7**
- Duplicate/similar findings detected: **7**
- WAF rule proposals allowed: **0**
- WAF proposals blocked/suppressed: **7**
- Agent modes used: **{'local_rules': 7}**
- Memory backends used: **{'sqlite_vector_memory': 7}**

## Risk Distribution

| Risk Level | Count |
|---|---:|
| medium | 6 |
| high | 1 |

## CWE Distribution

| CWE | Count |
|---|---:|
| CWE-20 | 2 |
| CWE-89 | 2 |
| CWE-79 | 2 |
| CWE-200 | 1 |

## Source Distribution

| Source | Count |
|---|---:|
| SAST | 7 |

## Highest Priority Findings

| Finding | Asset | CWE | Risk | Score | Reachable | WAF Allowed | Agent |
|---|---|---|---|---:|---|---|---|
| SEMGREP-003 | demo-vulnerable-app | CWE-89 | high | 0.682 | False | False | local_rules |
| SEMGREP-002 | demo-vulnerable-app | CWE-89 | medium | 0.625 | False | False | local_rules |
| SEMGREP-004 | demo-vulnerable-app | CWE-79 | medium | 0.608 | False | False | local_rules |
| SEMGREP-005 | demo-vulnerable-app | CWE-79 | medium | 0.608 | False | False | local_rules |
| SEMGREP-001 | demo-vulnerable-app | CWE-20 | medium | 0.587 | False | False | local_rules |
| SEMGREP-007 | demo-vulnerable-app | CWE-200 | medium | 0.582 | False | False | local_rules |
| SEMGREP-006 | demo-vulnerable-app | CWE-20 | medium | 0.528 | False | False | local_rules |

## Findings by Asset

### demo-vulnerable-app

- **SEMGREP-003** — CWE-89 / high / score `0.682`
  - Decision: review_duplicate_group
  - Reason: Mapped to CWE-89 (SQL Injection). Priority score is 0.68, categorized as high. Reachability is not confirmed, so exploitation likelihood is reduced. This appears similar to existing finding SEMGREP-003, so deduplication review is recommended. WAF proposal is blocked or not eligible under safety constraints.
  - Safety: Blocked WAF proposal: SAST-only signals cannot trigger WAF rule generation.
  - Human approval actions: review_remediation_plan, review_duplicate_grouping
- **SEMGREP-002** — CWE-89 / medium / score `0.625`
  - Decision: review_duplicate_group
  - Reason: Mapped to CWE-89 (SQL Injection). Priority score is 0.62, categorized as medium. Reachability is not confirmed, so exploitation likelihood is reduced. This appears similar to existing finding SEMGREP-002, so deduplication review is recommended. WAF proposal is blocked or not eligible under safety constraints.
  - Safety: Blocked WAF proposal: SAST-only signals cannot trigger WAF rule generation.
  - Human approval actions: review_duplicate_grouping
- **SEMGREP-004** — CWE-79 / medium / score `0.608`
  - Decision: review_duplicate_group
  - Reason: Mapped to CWE-79 (Cross-Site Scripting). Priority score is 0.61, categorized as medium. Reachability is not confirmed, so exploitation likelihood is reduced. This appears similar to existing finding SEMGREP-004, so deduplication review is recommended. WAF proposal is blocked or not eligible under safety constraints.
  - Safety: Blocked WAF proposal: SAST-only signals cannot trigger WAF rule generation.
  - Human approval actions: review_duplicate_grouping
- **SEMGREP-005** — CWE-79 / medium / score `0.608`
  - Decision: review_duplicate_group
  - Reason: Mapped to CWE-79 (Cross-Site Scripting). Priority score is 0.61, categorized as medium. Reachability is not confirmed, so exploitation likelihood is reduced. This appears similar to existing finding SEMGREP-004, so deduplication review is recommended. WAF proposal is blocked or not eligible under safety constraints.
  - Safety: Blocked WAF proposal: SAST-only signals cannot trigger WAF rule generation.
  - Human approval actions: review_duplicate_grouping
- **SEMGREP-001** — CWE-20 / medium / score `0.587`
  - Decision: review_duplicate_group
  - Reason: Mapped to CWE-20 (Improper Input Validation). Priority score is 0.59, categorized as medium. Reachability is not confirmed, so exploitation likelihood is reduced. This appears similar to existing finding SEMGREP-001, so deduplication review is recommended. WAF proposal is blocked or not eligible under safety constraints.
  - Safety: Blocked WAF proposal: SAST-only signals cannot trigger WAF rule generation.
  - Human approval actions: review_duplicate_grouping
- **SEMGREP-007** — CWE-200 / medium / score `0.582`
  - Decision: review_duplicate_group
  - Reason: Mapped to CWE-200 (Exposure of Sensitive Information). Priority score is 0.58, categorized as medium. Reachability is not confirmed, so exploitation likelihood is reduced. This appears similar to existing finding SEMGREP-007, so deduplication review is recommended. WAF proposal is blocked or not eligible under safety constraints.
  - Safety: Blocked WAF proposal: SAST-only signals cannot trigger WAF rule generation.
  - Human approval actions: review_duplicate_grouping
- **SEMGREP-006** — CWE-20 / medium / score `0.528`
  - Decision: review_duplicate_group
  - Reason: Mapped to CWE-20 (Improper Input Validation). Priority score is 0.53, categorized as medium. Reachability is not confirmed, so exploitation likelihood is reduced. This appears similar to existing finding SEMGREP-006, so deduplication review is recommended. WAF proposal is blocked or not eligible under safety constraints.
  - Safety: Blocked WAF proposal: SAST-only signals cannot trigger WAF rule generation.
  - Human approval actions: review_duplicate_grouping

## Notes for Discussion

- WAF rule eligibility is enforced by deterministic code, not by an LLM prompt.
- Priority scoring combines CVSS, classifier confidence, reachability, exploit availability, business criticality, and asset exposure.
- Duplicate detection uses lightweight local embeddings in the MVP; production upgrade can use Qdrant, Chroma, FAISS, or pgvector.
- The ML classifier is intentionally simple and replaceable; production should train on historical labeled findings and evaluate calibration.