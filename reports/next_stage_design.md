# Next Stage Design: From Rule MVP to Trainable ML Pipeline

## What changed in v2

The original MVP used deterministic local rules for CWE normalization and in-memory duplicate detection. Version 2 keeps that reliable baseline but adds a trainable ML path and better operational features.

## New capabilities

1. **Trainable CWE classifier**
   - Uses TF-IDF features + Logistic Regression.
   - Trains from `data/cwe_training_findings.jsonl`.
   - Saves model to `models/cwe_tfidf_logreg.joblib`.
   - Can be enabled with `--use-ml` or `?use_ml=true`.

2. **Persistent vulnerability memory**
   - CLI supports `--memory-file output/memory.json`.
   - Duplicate/similar findings can persist between runs.
   - This simulates organizational vulnerability memory.

3. **Batch Markdown report**
   - CLI supports `--report output/batch_report.md`.
   - Produces executive summary, risk distribution, CWE distribution, source distribution, and top findings.

4. **API memory summary**
   - FastAPI exposes `/memory/summary`.
   - Shows stored records, groups, CWEs, and assets.

5. **ML evaluation support**
   - `python -m app.evaluation.evaluate --use-ml` evaluates ML classifier mode.
   - Rule mode remains available for comparison.

## Why this architecture is still safe

The ML classifier only predicts CWE and confidence. It does not control dangerous actions. WAF rule eligibility is still enforced in deterministic code under `app/waf/waf_gate.py`.

This separation is intentional:

```text
ML predicts classification.
Scoring calculates priority.
WAF gate enforces safety policy.
Agent explains the result.
Human approval remains required.
```

## Production upgrade path

- Replace TF-IDF model with fine-tuned DistilBERT, CodeBERT, or DeBERTa.
- Replace hash embedding memory with Chroma, Qdrant, FAISS, or pgvector.
- Replace local agent with LangGraph + structured LLM output.
- Add real scanner adapters for Semgrep, ZAP, Dependency-Check, Snyk, and GitHub Code Scanning.
- Add calibration metrics such as Brier score and expected calibration error.
- Add drift detection and approval-feedback learning loop.
