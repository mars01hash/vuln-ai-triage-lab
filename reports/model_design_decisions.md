# Model Design Decisions

## Objective

Normalize heterogeneous vulnerability findings from SAST, DAST, and SCA tools into a canonical representation that supports CWE mapping, deduplication, reachability-aware scoring, and human-approved remediation workflows.

## Current MVP Design

- CWE normalization: deterministic keyword classifier
- Entity extraction: regex/rule-based extraction
- Deduplication: local hash embedding + cosine similarity
- Scoring: confidence-weighted priority score using CVSS, reachability, exploit availability, business criticality, asset exposure, and source category
- Agent: local deterministic LLM-style triage generator
- WAF: proposal-only generation with hard safety gates

## Key Safety Constraint

SAST-only findings are blocked from WAF rule generation because static-only evidence may contain false positives. WAF proposals require dynamic confirmation or explicit `dast_confirmed=true` plus high priority and reachability evidence.

## Upgrade Path

1. Replace rule-based CWE classifier with TF-IDF + Logistic Regression baseline.
2. Fine-tune a Transformer classifier for vulnerability descriptions.
3. Use sentence-transformers or OpenAI embeddings for semantic similarity.
4. Move memory from in-process list to Qdrant/Chroma/pgvector.
5. Use LangGraph + structured LLM outputs for triage and remediation text.
6. Add offline datasets and calibration metrics such as Brier score and reliability curves.
