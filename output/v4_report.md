# Vulnerability AI Triage Batch Report

## Executive Summary

- Total findings processed: **9**
- Duplicate/similar findings detected: **9**
- WAF rule proposals allowed: **3**
- WAF proposals blocked/suppressed: **6**
- Agent modes used: **{'local_rules': 9}**
- Memory backends used: **{'sqlite_vector_memory': 9}**

## Risk Distribution

| Risk Level | Count |
|---|---:|
| high | 5 |
| medium | 4 |

## CWE Distribution

| CWE | Count |
|---|---:|
| CWE-79 | 3 |
| CWE-89 | 2 |
| CWE-22 | 2 |
| CWE-798 | 1 |
| CWE-502 | 1 |

## Source Distribution

| Source | Count |
|---|---:|
| SAST | 4 |
| DAST | 3 |
| SCA | 2 |

## Highest Priority Findings

| Finding | Asset | CWE | Risk | Score | Reachable | WAF Allowed | Agent |
|---|---|---|---|---:|---|---|---|
| ZAP-001 | demo-vulnerable-app | CWE-89 | high | 0.781 | True | True | local_rules |
| ZAP-002 | demo-vulnerable-app | CWE-79 | high | 0.781 | True | True | local_rules |
| ZAP-003 | demo-vulnerable-app | CWE-22 | high | 0.781 | True | True | local_rules |
| SEMGREP-002 | demo-vulnerable-app | CWE-79 | high | 0.684 | True | False | local_rules |
| SEMGREP-001 | demo-vulnerable-app | CWE-89 | high | 0.683 | False | False | local_rules |
| SEMGREP-004 | demo-vulnerable-app | CWE-22 | medium | 0.666 | False | False | local_rules |
| DEPCHK-002 | demo-vulnerable-app | CWE-502 | medium | 0.642 | False | False | local_rules |
| DEPCHK-001 | demo-vulnerable-app | CWE-79 | medium | 0.615 | False | False | local_rules |
| SEMGREP-003 | demo-vulnerable-app | CWE-798 | medium | 0.608 | False | False | local_rules |

## Findings by Asset

### demo-vulnerable-app

- **ZAP-001** — CWE-89 / high / score `0.781`
  - Decision: review_duplicate_group
  - Reason: Mapped to CWE-89 (SQL Injection). Priority score is 0.78, categorized as high. Reachability evidence indicates the vulnerable path is reachable. This appears similar to existing finding ZAP-001, so deduplication review is recommended. A WAF virtual patch proposal can be reviewed by a human approver.
  - Safety: WAF rule is only a proposal and requires human approval before deployment.
  - Human approval actions: review_waf_virtual_patch, review_remediation_plan, review_duplicate_grouping
- **ZAP-002** — CWE-79 / high / score `0.781`
  - Decision: review_duplicate_group
  - Reason: Mapped to CWE-79 (Cross-Site Scripting). Priority score is 0.78, categorized as high. Reachability evidence indicates the vulnerable path is reachable. This appears similar to existing finding ZAP-002, so deduplication review is recommended. A WAF virtual patch proposal can be reviewed by a human approver.
  - Safety: WAF rule is only a proposal and requires human approval before deployment.
  - Human approval actions: review_waf_virtual_patch, review_remediation_plan, review_duplicate_grouping
- **ZAP-003** — CWE-22 / high / score `0.781`
  - Decision: review_duplicate_group
  - Reason: Mapped to CWE-22 (Path Traversal). Priority score is 0.78, categorized as high. Reachability evidence indicates the vulnerable path is reachable. This appears similar to existing finding ZAP-003, so deduplication review is recommended. A WAF virtual patch proposal can be reviewed by a human approver.
  - Safety: WAF rule is only a proposal and requires human approval before deployment.
  - Human approval actions: review_waf_virtual_patch, review_remediation_plan, review_duplicate_grouping
- **SEMGREP-002** — CWE-79 / high / score `0.684`
  - Decision: review_duplicate_group
  - Reason: Mapped to CWE-79 (Cross-Site Scripting). Priority score is 0.68, categorized as high. Reachability evidence indicates the vulnerable path is reachable. This appears similar to existing finding SEMGREP-002, so deduplication review is recommended. WAF proposal is blocked or not eligible under safety constraints.
  - Safety: Blocked WAF proposal: SAST-only signals cannot trigger WAF rule generation.
  - Human approval actions: review_remediation_plan, review_duplicate_grouping
- **SEMGREP-001** — CWE-89 / high / score `0.683`
  - Decision: review_duplicate_group
  - Reason: Mapped to CWE-89 (SQL Injection). Priority score is 0.68, categorized as high. Reachability is not confirmed, so exploitation likelihood is reduced. This appears similar to existing finding SEMGREP-001, so deduplication review is recommended. WAF proposal is blocked or not eligible under safety constraints.
  - Safety: Blocked WAF proposal: SAST-only signals cannot trigger WAF rule generation.
  - Human approval actions: review_remediation_plan, review_duplicate_grouping
- **SEMGREP-004** — CWE-22 / medium / score `0.666`
  - Decision: review_duplicate_group
  - Reason: Mapped to CWE-22 (Path Traversal). Priority score is 0.67, categorized as medium. Reachability is not confirmed, so exploitation likelihood is reduced. This appears similar to existing finding SEMGREP-004, so deduplication review is recommended. WAF proposal is blocked or not eligible under safety constraints.
  - Safety: Blocked WAF proposal: SAST-only signals cannot trigger WAF rule generation.
  - Human approval actions: review_duplicate_grouping
- **DEPCHK-002** — CWE-502 / medium / score `0.642`
  - Decision: review_duplicate_group
  - Reason: Mapped to CWE-502 (Deserialization of Untrusted Data). Priority score is 0.64, categorized as medium. Reachability is not confirmed, so exploitation likelihood is reduced. This appears similar to existing finding DEPCHK-002, so deduplication review is recommended. WAF proposal is blocked or not eligible under safety constraints.
  - Safety: Blocked WAF proposal: CWE-502 is not eligible for generic WAF virtual patching in this MVP.
  - Human approval actions: review_duplicate_grouping
- **DEPCHK-001** — CWE-79 / medium / score `0.615`
  - Decision: review_duplicate_group
  - Reason: Mapped to CWE-79 (Cross-Site Scripting). Priority score is 0.61, categorized as medium. Reachability is not confirmed, so exploitation likelihood is reduced. This appears similar to existing finding DEPCHK-001, so deduplication review is recommended. WAF proposal is blocked or not eligible under safety constraints.
  - Safety: Blocked WAF proposal: finding is not confirmed reachable.
  - Human approval actions: review_duplicate_grouping
- **SEMGREP-003** — CWE-798 / medium / score `0.608`
  - Decision: review_duplicate_group
  - Reason: Mapped to CWE-798 (Use of Hard-coded Credentials). Priority score is 0.61, categorized as medium. Reachability is not confirmed, so exploitation likelihood is reduced. This appears similar to existing finding SEMGREP-003, so deduplication review is recommended. WAF proposal is blocked or not eligible under safety constraints.
  - Safety: Blocked WAF proposal: SAST-only signals cannot trigger WAF rule generation.
  - Human approval actions: review_duplicate_grouping

## Notes for Discussion

- WAF rule eligibility is enforced by deterministic code, not by an LLM prompt.
- Priority scoring combines CVSS, classifier confidence, reachability, exploit availability, business criticality, and asset exposure.
- Duplicate detection uses lightweight local embeddings in the MVP; production upgrade can use Qdrant, Chroma, FAISS, or pgvector.
- The ML classifier is intentionally simple and replaceable; production should train on historical labeled findings and evaluate calibration.