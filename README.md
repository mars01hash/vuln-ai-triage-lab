# Vulnerability AI Triage Lab v2

A runnable AppSec AI MVP for **CWE normalization**, **entity extraction**, **deduplication**, **Bayesian-style priority scoring**, **reachability gating**, **LLM-style triage**, and **WAF proposal safety gating**.

Version 2 adds a trainable **scikit-learn CWE classifier**, persistent memory, Markdown batch reports, and ML evaluation mode.

---

## 1. What this project demonstrates

This project simulates the architecture needed for an AI-powered vulnerability intelligence system:

```text
SAST/DAST/SCA Findings
        ↓
Canonical Schema
        ↓
CWE Normalization
        ↓
Entity Extraction
        ↓
Duplicate/Similarity Memory
        ↓
Reachability Gate
        ↓
Bayesian-style Priority Score
        ↓
Triage + Fix Recommendation
        ↓
WAF Proposal Gate + Human Approval
```

The key design principle is:

> LLM/agent output should assist and explain. Safety-sensitive decisions must be enforced by deterministic code.

---

## 2. Setup

```bash
cd vuln-ai-triage-lab
python -m venv .venv
```

### Windows

```bash
.venv\Scripts\activate
```

### Linux/macOS

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 3. Run the rule-based MVP

```bash
python -m app.cli --input data/sample_findings_all.json --pretty
```

Save output:

```bash
python -m app.cli \
  --input data/sample_findings_all.json \
  --output output/results_rules.json \
  --pretty
```

---

## 4. Train the ML CWE classifier

```bash
python -m app.ml.train_cwe_classifier \
  --input data/cwe_training_findings.jsonl \
  --output models/cwe_tfidf_logreg.joblib \
  --metrics output/cwe_training_metrics.json
```

Or use the helper script:

### Windows

```bash
scripts\train_model.bat
```

### Linux/macOS

```bash
bash scripts/train_model.sh
```

---

## 5. Run with the trained ML classifier

```bash
python -m app.cli \
  --input data/sample_findings_all.json \
  --use-ml \
  --pretty
```

Save output + report:

```bash
python -m app.cli \
  --input data/sample_findings_all.json \
  --use-ml \
  --output output/results_ml.json \
  --report output/batch_report.md \
  --pretty
```

---

## 6. Use persistent vulnerability memory

This simulates organizational vulnerability memory across runs.

```bash
python -m app.cli \
  --input data/sample_findings_all.json \
  --memory-file output/memory.json \
  --output output/run_1.json \
  --pretty
```

Run the same command again and you should see more duplicate/similar findings because previous records were stored.

---

## 7. Run evaluation

Rule-based evaluation:

```bash
python -m app.evaluation.evaluate --input data/eval_labeled_findings.json
```

ML evaluation:

```bash
python -m app.evaluation.evaluate \
  --input data/eval_labeled_findings.json \
  --use-ml \
  --model-path models/cwe_tfidf_logreg.joblib
```

---

## 8. Run FastAPI server

```bash
uvicorn app.main:app --reload
```

Open:

```text
http://127.0.0.1:8000/docs
```

Main endpoints:

| Endpoint | Purpose |
|---|---|
| `POST /triage` | Triage one finding |
| `POST /triage/batch` | Triage multiple findings |
| `GET /memory/summary` | Show API memory stats |

Use ML mode by adding query parameter:

```text
POST /triage?use_ml=true
```

Make sure you train the model first.

---

## 9. Run tests

```bash
pytest
```

---

## 10. Interview explanation

You can explain the project like this:

> I built a modular vulnerability intelligence pipeline. The ingestion layer normalizes scanner findings, the CWE module maps heterogeneous findings into a canonical weakness taxonomy, the memory module detects duplicate/similar findings, reachability reduces SAST noise, scoring produces an auditable priority score, and the agent layer generates triage/fix recommendations. WAF rule eligibility is enforced outside the LLM through deterministic system-level safety gates.

---

## 11. Current MVP vs production upgrade

| Area | Current v2 | Production upgrade |
|---|---|---|
| CWE classifier | TF-IDF + Logistic Regression | Fine-tuned Transformer / CodeBERT |
| Embeddings | Hash-based vectors | Sentence-Transformers / BGE / OpenAI embeddings |
| Vector DB | JSON/in-memory | Qdrant / Chroma / FAISS / pgvector |
| Agent | Local deterministic triage | LangGraph + structured LLM output |
| Reachability | Simple/mock gate | CodeQL / Joern / real callgraph/data-flow |
| WAF | Proposal only | ModSecurity/Cloudflare/AWS WAF approval workflow |
| Evaluation | Basic accuracy | Calibration, rank metrics, drift, approval feedback |

---

## 12. Files to inspect first

| File | Why important |
|---|---|
| `app/pipeline.py` | Main orchestration flow |
| `app/schemas.py` | Canonical vulnerability schema |
| `app/ml/train_cwe_classifier.py` | Trainable CWE classifier |
| `app/ml/cwe_ml_classifier.py` | ML prediction wrapper |
| `app/scoring/bayesian_score.py` | Priority scoring logic |
| `app/waf/waf_gate.py` | Safety gate for WAF proposals |
| `app/reporting/report_writer.py` | Batch Markdown report |
| `reports/next_stage_design.md` | Design reasoning for v2 |
