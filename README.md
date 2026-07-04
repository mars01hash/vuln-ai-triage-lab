# Vulnerability AI Triage Lab v3

A runnable AppSec AI project for **CWE normalization**, **ML classification**, **entity extraction**, **persistent vector-style vulnerability memory**, **deduplication**, **Bayesian-style priority scoring**, **reachability gating**, **optional LLM triage**, **WAF policy gating**, and **human feedback logging**.

Version 3 upgrades v2 with:

- SQLite-backed persistent vector memory
- Embedding provider abstraction
- Optional Sentence-Transformers / Chroma upgrade path
- Optional OpenAI LLM triage agent with local fallback
- Human approval action policy
- Human feedback API
- Better report fields for agent mode and memory backend
- Docker Compose support

---

## 1. Architecture

```text
SAST / DAST / SCA Findings
        ↓
Canonical Schema
        ↓
CWE Normalization
  ├─ rule-based mode
  └─ ML TF-IDF + Logistic Regression mode
        ↓
Entity Extraction
        ↓
Vector Memory / Deduplication
  ├─ default: SQLite + hash embeddings
  └─ optional: Chroma + Sentence-Transformers
        ↓
Reachability Gate
        ↓
Bayesian-style Priority Score
        ↓
WAF Proposal Gate
        ↓
Agentic Triage Explanation
  ├─ default: local deterministic agent
  └─ optional: OpenAI JSON agent with fallback
        ↓
Human Approval / Feedback Loop
```

Main design principle:

> LLMs explain and assist. Classification, scoring, WAF eligibility, and human approval gates are enforced by deterministic code.

---

## 2. Setup

```bash
cd vuln-ai-triage-lab-v3
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

Install default runnable dependencies:

```bash
pip install -r requirements.txt
```

Optional advanced dependencies:

```bash
pip install -r requirements-advanced.txt
```

Default mode does **not** require OpenAI, Chroma, Sentence-Transformers, or a GPU.

---

## 3. Train the ML CWE classifier

```bash
python -m app.ml.train_cwe_classifier \
  --input data/cwe_training_findings.jsonl \
  --output models/cwe_tfidf_logreg.joblib \
  --metrics output/cwe_training_metrics.json
```

---

## 4. Run v3 CLI demo

```bash
python -m app.cli \
  --input data/sample_findings_all.json \
  --use-ml \
  --memory-backend sqlite \
  --memory-file output/v3_memory.sqlite \
  --output output/v3_results.json \
  --report output/v3_report.md \
  --pretty
```

Fast script:

### Windows

```bash
scripts\run_v3_demo.bat
```

### Linux/macOS

```bash
./scripts/run_v3_demo.sh
```

---

## 5. Optional LLM triage mode

The project runs locally without LLMs. To enable OpenAI triage text:

```bash
pip install -r requirements-advanced.txt
set OPENAI_API_KEY=your_key_here   # Windows CMD
# or
export OPENAI_API_KEY=your_key_here
```

Then run:

```bash
python -m app.cli \
  --input data/sample_findings_all.json \
  --use-ml \
  --use-llm \
  --llm-model gpt-4o-mini \
  --memory-backend sqlite \
  --memory-file output/v3_memory.sqlite \
  --pretty
```

If the key or package is missing, the system falls back to local deterministic triage and records that in `agent_mode`.

---

## 6. Run FastAPI server

```bash
uvicorn app.main:app --reload
```

Open:

```text
http://127.0.0.1:8000/docs
```

Useful endpoints:

| Endpoint | Purpose |
|---|---|
| `POST /triage` | Triage one finding |
| `POST /triage/batch` | Triage many findings |
| `GET /memory/summary` | SQLite vector memory summary |
| `POST /feedback` | Save human reviewer feedback |
| `GET /feedback/summary` | Feedback counts |

Example query flags:

```text
POST /triage?use_ml=true&use_llm=false
POST /triage/batch?use_ml=true&use_llm=true&llm_model=gpt-4o-mini
```

---

## 7. Run tests

```bash
pytest
```

---

## 8. Run evaluation

Rule mode:

```bash
python -m app.evaluation.evaluate --input data/eval_labeled_findings.json
```

ML mode:

```bash
python -m app.evaluation.evaluate --input data/eval_labeled_findings.json --use-ml
```

---

## 9. Docker

```bash
docker compose up --build
```

Then open:

```text
http://127.0.0.1:8000/docs
```

---

## 10. What makes v3 different from v2?

| Area | v2 | v3 |
|---|---|---|
| Memory | JSON/in-memory | SQLite vector-style persistent memory by default |
| Embeddings | Hash only | Embedding provider abstraction + optional Sentence-Transformers |
| Vector DB | Not included | SQLite default + optional Chroma adapter |
| Agent | Local deterministic | Local + optional OpenAI JSON LLM with fallback |
| Approval | WAF human approval flag | Explicit approval action policy |
| Feedback | Not included | Human feedback JSONL store + API endpoints |
| Reporting | Basic batch report | Adds agent mode, memory backend, approval actions |

---

## 11. Interview explanation

You can explain v3 like this:

> I designed the system as a modular AppSec AI pipeline. Scanner outputs are converted to a canonical vulnerability schema, then CWE-normalized using either rules or a trainable ML classifier. Findings are embedded and stored in persistent SQLite vector memory for deduplication and organizational memory. A reachability gate and Bayesian-style scoring layer prioritize findings using CVSS, exploitability, business context, and confidence. The LLM agent is optional and only generates triage explanation text; safety-sensitive decisions like WAF eligibility and approval requirements are enforced by deterministic policy code.

That answer directly matches the company’s requirements around CWE normalization, vector retrieval, Bayesian scoring, agentic triage, and system-level human approval gates.
