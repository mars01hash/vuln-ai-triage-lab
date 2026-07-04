# Vulnerability AI Triage Batch Report

## Executive Summary

- Total findings processed: **7**
- Duplicate/similar findings detected: **0**
- WAF rule proposals allowed: **1**
- WAF proposals blocked/suppressed: **6**

## Risk Distribution

| Risk Level | Count |
|---|---:|
| high | 3 |
| medium | 3 |
| critical | 1 |

## CWE Distribution

| CWE | Count |
|---|---:|
| CWE-89 | 2 |
| CWE-79 | 2 |
| CWE-798 | 1 |
| CWE-20 | 1 |
| CWE-22 | 1 |

## Source Distribution

| Source | Count |
|---|---:|
| SAST | 3 |
| DAST | 2 |
| SCA | 2 |

## Highest Priority Findings

| Finding | Asset | CWE | Risk | Score | Reachable | WAF Allowed |
|---|---|---|---|---:|---|---|
| DAST-001 | payment-api | CWE-89 | critical | 0.853 | True | True |
| SAST-001 | payment-api | CWE-89 | high | 0.814 | True | False |
| SCA-001 | reporting-service | CWE-20 | high | 0.734 | False | False |
| DAST-002 | customer-portal | CWE-79 | high | 0.726 | True | False |
| SAST-003 | customer-portal | CWE-79 | medium | 0.656 | True | False |
| SCA-002 | document-service | CWE-22 | medium | 0.642 | False | False |
| SAST-002 | billing-worker | CWE-798 | medium | 0.617 | False | False |

## Findings by Asset

### billing-worker

- **SAST-002** — CWE-798 / medium / score `0.617`
  - Decision: deprioritize_until_reachability_confirmed
  - Reason: Mapped to CWE-798 (Use of Hard-coded Credentials). Priority score is 0.62, categorized as medium. Reachability is not confirmed, so exploitation likelihood is reduced. WAF proposal is blocked or not eligible under safety constraints.
  - Safety: Blocked WAF proposal: SAST-only signals cannot trigger WAF rule generation.

### customer-portal

- **DAST-002** — CWE-79 / high / score `0.726`
  - Decision: urgent_fix_required
  - Reason: Mapped to CWE-79 (Cross-Site Scripting). Priority score is 0.73, categorized as high. Reachability evidence indicates the vulnerable path is reachable. WAF proposal is blocked or not eligible under safety constraints.
  - Safety: Blocked WAF proposal: priority score below WAF proposal threshold 0.75.
- **SAST-003** — CWE-79 / medium / score `0.656`
  - Decision: standard_security_backlog
  - Reason: Mapped to CWE-79 (Cross-Site Scripting). Priority score is 0.66, categorized as medium. Reachability evidence indicates the vulnerable path is reachable. WAF proposal is blocked or not eligible under safety constraints.
  - Safety: Blocked WAF proposal: SAST-only signals cannot trigger WAF rule generation.

### document-service

- **SCA-002** — CWE-22 / medium / score `0.642`
  - Decision: deprioritize_until_reachability_confirmed
  - Reason: Mapped to CWE-22 (Path Traversal). Priority score is 0.64, categorized as medium. Reachability is not confirmed, so exploitation likelihood is reduced. WAF proposal is blocked or not eligible under safety constraints.
  - Safety: Blocked WAF proposal: finding is not confirmed reachable.

### payment-api

- **DAST-001** — CWE-89 / critical / score `0.853`
  - Decision: urgent_fix_required
  - Reason: Mapped to CWE-89 (SQL Injection). Priority score is 0.85, categorized as critical. Reachability evidence indicates the vulnerable path is reachable. A WAF virtual patch proposal can be reviewed by a human approver.
  - Safety: WAF rule is only a proposal and requires human approval before deployment.
- **SAST-001** — CWE-89 / high / score `0.814`
  - Decision: urgent_fix_required
  - Reason: Mapped to CWE-89 (SQL Injection). Priority score is 0.81, categorized as high. Reachability evidence indicates the vulnerable path is reachable. WAF proposal is blocked or not eligible under safety constraints.
  - Safety: Blocked WAF proposal: SAST-only signals cannot trigger WAF rule generation.

### reporting-service

- **SCA-001** — CWE-20 / high / score `0.734`
  - Decision: deprioritize_until_reachability_confirmed
  - Reason: Mapped to CWE-20 (Improper Input Validation). Priority score is 0.73, categorized as high. Reachability is not confirmed, so exploitation likelihood is reduced. WAF proposal is blocked or not eligible under safety constraints.
  - Safety: Blocked WAF proposal: CWE-20 is not eligible for generic WAF virtual patching in this MVP.

## Notes for Interview Discussion

- WAF rule eligibility is enforced by deterministic code, not by an LLM prompt.
- Priority scoring combines CVSS, classifier confidence, reachability, exploit availability, business criticality, and asset exposure.
- Duplicate detection uses lightweight local embeddings in the MVP; production upgrade can use Qdrant, Chroma, FAISS, or pgvector.
- The ML classifier is intentionally simple and replaceable; production should train on historical labeled findings and evaluate calibration.