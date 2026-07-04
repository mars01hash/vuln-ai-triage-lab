# Vuln AI Triage Lab

A runnable MVP for an AI-assisted AppSec vulnerability intelligence pipeline.

It ingests SAST/DAST/SCA-style findings, normalizes them into canonical CWE classes, extracts entities, deduplicates semantically similar findings, calculates a priority score, and produces triage/fix/WAF proposal outputs with hard safety gates.

> This project is intentionally runnable without paid APIs. The first version uses local rule-based NLP + hash embeddings. You can later replace modules with Hugging Face models, Chroma/Qdrant, OpenAI/Claude/Gemini, CodeQL, etc.

---

## Features

- Canonical vulnerability schema using Pydantic
- Sample SAST, DAST, and SCA findings
- CWE normalization for common weakness classes
- Regex/rule-based entity extraction
- Lightweight embedding-based deduplication using pure Python hashing
- Priority scoring inspired by Bayesian/confidence-weighted risk scoring
- Reachability gate
- WAF rule proposal gate with strict rule: **SAST-only findings do not generate WAF rules**
- Local LLM-style triage agent using deterministic rules
- CLI demo
- FastAPI API demo
- Evaluation script
- Pytest smoke tests

---

## Project Structure

```text
vuln-ai-triage-lab/
├── app/
│   ├── main.py                     # FastAPI app
│   ├── cli.py                      # CLI runner
│   ├── pipeline.py                 # End-to-end pipeline
│   ├── schemas.py                  # Pydantic models
│   ├── ingestion/                  # JSON adapters
│   ├── normalization/              # CWE classifier + entity extraction
│   ├── retrieval/                  # Hash embeddings + cosine similarity
│   ├── scoring/                    # Priority scoring
│   ├── reachability/               # Reachability gate
│   ├── agents/                     # Triage/fix agent
│   ├── waf/                        # WAF proposal gate
│   ├── storage/                    # In-memory vulnerability memory
│   └── evaluation/                 # Evaluation helpers
├── data/
│   ├── sample_sast_findings.json
│   ├── sample_dast_findings.json
│   ├── sample_sca_findings.json
│   └── sample_findings_all.json
├── reports/
├── tests/
├── requirements.txt
├── Dockerfile
└── pyproject.toml
```

---

## Quick Start

### 1. Create virtual environment

```bash
python -m venv .venv
```

Windows:

```bash
.venv\Scripts\activate
```

Linux/macOS:

```bash
source .venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run CLI demo

```bash
python -m app.cli --input data/sample_findings_all.json --pretty
```

You should get normalized vulnerability results like:

```json
{
  "finding_id": "SAST-001",
  "canonical_cwe": "CWE-89",
  "risk_level": "critical",
  "waf_rule_allowed": false,
  "human_approval_required": true
}
```

### 4. Run FastAPI server

```bash
uvicorn app.main:app --reload
```

Open:

```text
http://127.0.0.1:8000/docs
```

### 5. Test API with curl

```bash
curl -X POST "http://127.0.0.1:8000/triage" ^
  -H "Content-Type: application/json" ^
  -d @data/sample_findings_all.json
```

For Linux/macOS, replace `^` with `\`.

### 6. Run tests

```bash
pytest
```

---

## API Endpoints

### Health Check

```http
GET /health
```

### Triage Findings

```http
POST /triage
```

Body:

```json
[
  {
    "finding_id": "SAST-001",
    "source_type": "SAST",
    "tool_name": "Semgrep",
    "title": "Possible SQL Injection",
    "description": "User input from parameter id reaches raw SQL query",
    "cvss": 8.8,
    "asset": "payment-api",
    "endpoint": "/api/orders",
    "parameter": "id",
    "reachable": true,
    "business_criticality": "high",
    "asset_exposure": "internet",
    "exploit_available": true
  }
]
```

---

## Important Safety Rules Implemented

### 1. SAST-only cannot generate WAF rule

```python
if finding.source_type == "SAST" and not finding.dast_confirmed:
    waf_rule_allowed = False
```

### 2. Human approval required for WAF proposal

Even when WAF rule is allowed, output marks:

```json
"human_approval_required": true
```

### 3. LLM-style agent is advisory only

The agent produces triage text and fix advice, but hard constraints are enforced in code.

---

## How to Extend This MVP

### Replace local CWE classifier

Current:

```text
Rule-based keyword classifier
```

Upgrade:

```text
TF-IDF + Logistic Regression
Hugging Face Transformer classifier
CodeBERT for code-aware findings
```

### Replace local embeddings

Current:

```text
Pure Python hash embedding
```

Upgrade:

```text
sentence-transformers/all-MiniLM-L6-v2
BAAI/bge-small-en-v1.5
OpenAI embeddings
```

### Replace in-memory vector memory

Current:

```text
In-memory Python list
```

Upgrade:

```text
ChromaDB
Qdrant
FAISS
PostgreSQL pgvector
```

### Replace local triage agent

Current:

```text
Rule-based LLM-style triage
```

Upgrade:

```text
LangGraph + GPT-5.5 / GPT-5.4 mini
Structured Outputs + Pydantic validation
MCP tools for repo, ticketing, scanner, and WAF approval workflow
```

---

## Interview Talking Point

> I built a vulnerability intelligence prototype that normalizes heterogeneous SAST, DAST, and SCA findings into canonical CWE labels, deduplicates findings through embedding similarity, applies reachability and business context, computes an explainable priority score, and produces LLM-style triage/fix/WAF proposal outputs with code-enforced human approval gates.

---

## Disclaimer

This is a portfolio/training MVP, not a production security tool. Do not use the WAF proposals directly in production without expert review and controlled testing.
