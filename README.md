# Vulnerability AI Triage Lab v4 🔐🤖

A runnable AppSec AI portfolio project that ingests scanner findings, normalizes them to CWE, deduplicates similar issues using vector-style memory, scores priority with explainable evidence, generates triage/fix recommendations, and enforces WAF/human-approval safety gates.

v4 is designed to match a senior **ML / Applied AI / AppSec Intelligence** job description.

---

## What v4 Adds

| Feature | Status |
|---|---|
| Real-scanner-style adapters | Semgrep, OWASP ZAP, Dependency-Check |
| Offline scanner fixtures | Included and runnable immediately |
| Demo vulnerable app | Flask app with SQLi, XSS, path traversal, hardcoded secret |
| Streamlit dashboard | Included |
| Full benchmark command | Included |
| Docker Compose | API + dashboard + demo app |
| ML CWE classifier | TF-IDF + Logistic Regression |
| Persistent memory | SQLite vector-style memory |
| Optional LLM triage | Safe fallback if no API key |
| WAF safety gate | SAST-only findings cannot generate WAF rules |

---

## Architecture

```text
Security scanner outputs
Semgrep / OWASP ZAP / Dependency-Check
        ↓
Scanner adapters
        ↓
Canonical VulnerabilityFinding schema
        ↓
CWE normalization: rules or ML classifier
        ↓
Entity extraction
        ↓
Vector-style memory deduplication
        ↓
Reachability gate
        ↓
Bayesian-style priority scoring
        ↓
Local or optional LLM triage agent
        ↓
WAF proposal gate
        ↓
Human approval policy
        ↓
API / dashboard / reports / benchmark
```

---

## Quick Start

```bash
cd vuln-ai-triage-lab-v4
python -m venv .venv
```

### Windows

```bash
.venv\Scripts\activate
```

### Linux / macOS

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Train the ML CWE classifier:

```bash
python -m app.ml.train_cwe_classifier --input data/cwe_training_findings.jsonl --output models/cwe_tfidf_logreg.joblib --metrics output/cwe_training_metrics.json
```

Generate canonical findings from scanner fixtures:

```bash
python -m app.scanners.run_all --output output/scanner_findings_all.json
```

Run the v4 AI pipeline:

```bash
python -m app.cli --input output/scanner_findings_all.json --use-ml --memory-backend sqlite --memory-file output/v4_memory.sqlite --output output/v4_results.json --report output/v4_report.md --pretty
```

Run the full benchmark:

```bash
python -m app.evaluation.full_benchmark --use-ml --output output/full_benchmark_metrics.json --report output/full_benchmark_report.md
```

Run all v4 demo steps:

```bash
bash scripts/run_v4_demo.sh
```

On Windows:

```bat
scripts\run_v4_demo.bat
```

---

## Run the API

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
| `POST /triage/batch` | Triage a list of findings |
| `GET /demo/scanner-fixtures` | Convert bundled scanner fixtures into canonical findings |
| `POST /demo/scanner-fixtures/triage` | Run full triage over bundled scanner fixtures |
| `GET /memory/summary` | Check persistent memory summary |
| `POST /feedback` | Add human review feedback |

---

## Run the Dashboard

First create scanner findings:

```bash
python -m app.scanners.run_all --output output/scanner_findings_all.json
```

Then run:

```bash
streamlit run app/dashboard/streamlit_app.py
```

Open:

```text
http://localhost:8501
```

Dashboard shows:

- total findings
- risk distribution
- CWE distribution
- findings table
- duplicate status
- WAF proposal status
- triage reasoning
- recommended fix
- raw structured output

---

## Scanner Integration

### Offline fixture mode

These commands work even if the scanner tools are not installed:

```bash
python -m app.scanners.run_semgrep --sample --output output/semgrep_findings.json
python -m app.scanners.run_zap --sample --output output/zap_findings.json
python -m app.scanners.run_dependency_check --sample --output output/dependency_check_findings.json
```

### Real scanner mode

If installed, you can run real tools:

```bash
python -m app.scanners.run_semgrep --target demo-vulnerable-app --output output/semgrep_findings.json
python -m app.scanners.run_zap --target http://localhost:5000 --output output/zap_findings.json
python -m app.scanners.run_dependency_check --target demo-vulnerable-app --output output/dependency_check_findings.json
```

The runner will fall back to fixtures when tools are unavailable if you use `--sample`.

---

## Demo Vulnerable App

The project includes:

```text
demo-vulnerable-app/
```

Intentional vulnerabilities:

| Route / Item | Vulnerability | CWE |
|---|---|---|
| `/user?id=1` | SQL Injection | CWE-89 |
| `/search?q=test` | Reflected XSS | CWE-79 |
| `/download?file=sample.txt` | Path Traversal | CWE-22 |
| `API_KEY` in source | Hard-coded secret | CWE-798 |
| `requirements.txt` | Vulnerable dependency examples | SCA/CVE |

Run locally:

```bash
cd demo-vulnerable-app
pip install flask
python app.py
```

Do not deploy the demo vulnerable app publicly.

---

## Docker Compose

```bash
docker compose up --build
```

Services:

| Service | URL |
|---|---|
| API | `http://localhost:8000/docs` |
| Dashboard | `http://localhost:8501` |
| Demo vulnerable app | `http://localhost:5000` |

---

## Tests

```bash
pytest
```

---

## Explanation


> I designed the system as a modular vulnerability intelligence pipeline. Scanner adapters isolate schema inconsistencies from SAST, DAST, and SCA tools. The canonical schema feeds CWE normalization, entity extraction, deduplication, reachability checks, and explainable priority scoring. The triage agent generates human-readable guidance, but safety-sensitive actions like WAF rule eligibility are enforced by deterministic code outside the LLM. The benchmark measures CWE accuracy, ranking quality, WAF false positives, and structured output validity.

---

## Current Limitations

- The bundled scanner outputs are fixtures unless real tools are installed.
- The ML classifier is a small baseline model, not a production transformer.
- Reachability is still a lightweight heuristic layer.
- WAF rules are proposals only; there is no automatic deployment.
- LLM integration is optional and safely falls back to local triage.

---

## Recommended v5 Direction

- Add real CodeQL/Joern reachability analysis.
- Replace baseline ML with a fine-tuned transformer or CodeBERT-style classifier.
- Add Qdrant or pgvector as the default vector store.
- Add LangGraph multi-agent flow for triage, remediation, validation, and reviewer approval.
- Add CI/CD pipeline with benchmark gating before model updates.
