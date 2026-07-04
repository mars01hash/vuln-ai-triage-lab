# Vulnerability AI Triage Batch Report

## Executive Summary

- Total findings processed: **9**
- Duplicate/similar findings detected: **1**
- WAF rule proposals allowed: **3**
- WAF proposals blocked/suppressed: **6**
- Agent modes used: **{'local_rules': 9}**
- Memory backends used: **{'sqlite_vector_memory': 9}**

## Risk Distribution

| Risk Level | Count |
|---|---:|
| high | 7 |
| critical | 2 |

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
| ZAP-001 | demo-vulnerable-app | CWE-89 | critical | 0.887 | True | True | local_rules |
| ZAP-002 | demo-vulnerable-app | CWE-79 | critical | 0.887 | True | True | local_rules |
| ZAP-003 | demo-vulnerable-app | CWE-22 | high | 0.781 | True | True | local_rules |
| SEMGREP-002 | demo-vulnerable-app | CWE-79 | high | 0.778 | True | False | local_rules |
| SEMGREP-001 | demo-vulnerable-app | CWE-89 | high | 0.776 | False | False | local_rules |
| SEMGREP-004 | demo-vulnerable-app | CWE-22 | high | 0.756 | False | False | local_rules |
| DEPCHK-002 | demo-vulnerable-app | CWE-502 | high | 0.729 | False | False | local_rules |
| DEPCHK-001 | demo-vulnerable-app | CWE-79 | high | 0.699 | False | False | local_rules |
| SEMGREP-003 | demo-vulnerable-app | CWE-798 | high | 0.691 | False | False | local_rules |

## Findings by Asset

### demo-vulnerable-app

- **ZAP-001** — CWE-89 / critical / score `0.887`
  - Decision: urgent_fix_required
  - Reason: Mapped to CWE-89 (SQL Injection). Priority score is 0.89, categorized as critical. Reachability evidence indicates the vulnerable path is reachable. A WAF virtual patch proposal can be reviewed by a human approver.
  - Safety: WAF rule is only a proposal and requires human approval before deployment.
  - Human approval actions: review_waf_virtual_patch, review_remediation_plan
- **ZAP-002** — CWE-79 / critical / score `0.887`
  - Decision: urgent_fix_required
  - Reason: Mapped to CWE-79 (Cross-Site Scripting). Priority score is 0.89, categorized as critical. Reachability evidence indicates the vulnerable path is reachable. A WAF virtual patch proposal can be reviewed by a human approver.
  - Safety: WAF rule is only a proposal and requires human approval before deployment.
  - Human approval actions: review_waf_virtual_patch, review_remediation_plan
- **ZAP-003** — CWE-22 / high / score `0.781`
  - Decision: review_duplicate_group
  - Reason: Mapped to CWE-22 (Path Traversal). Priority score is 0.78, categorized as high. Reachability evidence indicates the vulnerable path is reachable. This appears similar to existing finding SEMGREP-004, so deduplication review is recommended. A WAF virtual patch proposal can be reviewed by a human approver.
  - Safety: WAF rule is only a proposal and requires human approval before deployment.
  - Human approval actions: review_waf_virtual_patch, review_remediation_plan, review_duplicate_grouping
- **SEMGREP-002** — CWE-79 / high / score `0.778`
  - Decision: urgent_fix_required
  - Reason: Mapped to CWE-79 (Cross-Site Scripting). Priority score is 0.78, categorized as high. Reachability evidence indicates the vulnerable path is reachable. WAF proposal is blocked or not eligible under safety constraints.
  - Safety: Blocked WAF proposal: SAST-only signals cannot trigger WAF rule generation.
  - Human approval actions: review_remediation_plan
- **SEMGREP-001** — CWE-89 / high / score `0.776`
  - Decision: deprioritize_until_reachability_confirmed
  - Reason: Mapped to CWE-89 (SQL Injection). Priority score is 0.78, categorized as high. Reachability is not confirmed, so exploitation likelihood is reduced. WAF proposal is blocked or not eligible under safety constraints.
  - Safety: Blocked WAF proposal: SAST-only signals cannot trigger WAF rule generation.
  - Human approval actions: review_remediation_plan
- **SEMGREP-004** — CWE-22 / high / score `0.756`
  - Decision: deprioritize_until_reachability_confirmed
  - Reason: Mapped to CWE-22 (Path Traversal). Priority score is 0.76, categorized as high. Reachability is not confirmed, so exploitation likelihood is reduced. WAF proposal is blocked or not eligible under safety constraints.
  - Safety: Blocked WAF proposal: SAST-only signals cannot trigger WAF rule generation.
  - Human approval actions: review_remediation_plan
- **DEPCHK-002** — CWE-502 / high / score `0.729`
  - Decision: deprioritize_until_reachability_confirmed
  - Reason: Mapped to CWE-502 (Deserialization of Untrusted Data). Priority score is 0.73, categorized as high. Reachability is not confirmed, so exploitation likelihood is reduced. WAF proposal is blocked or not eligible under safety constraints.
  - Safety: Blocked WAF proposal: CWE-502 is not eligible for generic WAF virtual patching in this MVP.
  - Human approval actions: review_remediation_plan
- **DEPCHK-001** — CWE-79 / high / score `0.699`
  - Decision: deprioritize_until_reachability_confirmed
  - Reason: Mapped to CWE-79 (Cross-Site Scripting). Priority score is 0.70, categorized as high. Reachability is not confirmed, so exploitation likelihood is reduced. WAF proposal is blocked or not eligible under safety constraints.
  - Safety: Blocked WAF proposal: finding is not confirmed reachable.
  - Human approval actions: review_remediation_plan
- **SEMGREP-003** — CWE-798 / high / score `0.691`
  - Decision: deprioritize_until_reachability_confirmed
  - Reason: Mapped to CWE-798 (Use of Hard-coded Credentials). Priority score is 0.69, categorized as high. Reachability is not confirmed, so exploitation likelihood is reduced. WAF proposal is blocked or not eligible under safety constraints.
  - Safety: Blocked WAF proposal: SAST-only signals cannot trigger WAF rule generation.
  - Human approval actions: review_remediation_plan

## Notes for Discussion

- WAF rule eligibility is enforced by deterministic code, not by an LLM prompt.
- Priority scoring combines CVSS, classifier confidence, reachability, exploit availability, business criticality, and asset exposure.
- Duplicate detection uses lightweight local embeddings in the MVP; production upgrade can use Qdrant, Chroma, FAISS, or pgvector.
- The ML classifier is intentionally simple and replaceable; production should train on historical labeled findings and evaluate calibration.