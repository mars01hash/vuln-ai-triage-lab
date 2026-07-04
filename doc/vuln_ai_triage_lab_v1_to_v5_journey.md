# Vulnerability AI Triage Lab — Complete Project Journey from v1 to v5

## 1. Project Overview

**Project name:** `vuln-ai-triage-lab`  
**Domain:** Machine Learning + Application Security + LLM-assisted vulnerability intelligence  
**Goal:** Build a runnable portfolio project that demonstrates how AI can help security teams normalize, deduplicate, prioritize, triage, and safely respond to vulnerability findings from SAST, DAST, and SCA tools.

The project was designed to match a senior ML/AppSec AI job description that asked for:

- NLP-based CWE normalization
- Text classification and entity extraction
- Embedding-based similarity and vulnerability memory
- Bayesian/confidence-weighted scoring
- Reachability-aware prioritization
- Agentic AI triage and remediation support
- WAF/virtual patch proposal logic
- Human approval gates
- Evaluation, calibration, auditability, and feedback loops
- Scanner schema normalization across SAST, DAST, and SCA sources

The project evolved through five versions:

```text
v1 = Runnable local MVP
v2 = Trainable ML classifier + reporting
v3 = Persistent vector-style memory + optional LLM/vector architecture
v4 = Scanner integration + vulnerable demo app + dashboard
v5 = Calibration, auditability, feedback loop, threat intel, reachability evidence
```

The core design principle across all versions is:

> LLMs may assist with triage and explanation, but security-sensitive decisions such as WAF eligibility, human approval, and action policy must be enforced by deterministic system logic.

---

## 2. Business Problem

Security teams receive large numbers of vulnerability findings from different tools:

- **SAST** tools scan source code.
- **DAST** tools scan running applications.
- **SCA** tools scan dependencies and packages.

These tools often produce inconsistent output schemas, noisy findings, duplicate reports, and conflicting severity levels.

A typical problem looks like this:

```text
Semgrep says: "Unsanitized input reaches SQL query"
OWASP ZAP says: "SQL Injection detected at /orders?id=1"
Dependency-Check says: "Package has a CVE"
```

The system must answer:

1. What is the actual weakness?
2. Which CWE does it map to?
3. Is it a duplicate of a known finding?
4. Is the vulnerable code actually reachable?
5. Is there exploit evidence?
6. Is the affected system business-critical?
7. Should this be urgent?
8. Should a WAF rule be proposed?
9. Does a human need to approve the action?
10. How can developers fix it?

That is why the project architecture follows this pipeline:

```text
Scanner Findings
    ↓
Canonical Schema
    ↓
CWE Normalization
    ↓
Entity Extraction
    ↓
Vector Memory / Deduplication
    ↓
Reachability Evidence
    ↓
Threat Intelligence Enrichment
    ↓
Bayesian-style Priority Scoring
    ↓
Agentic Triage / Fix Recommendation
    ↓
WAF Safety Gate
    ↓
Human Approval / Feedback / Audit Log
```

---

## 3. Overall Architecture Philosophy

The project is intentionally modular.

Each module has one responsibility:

| Layer | Responsibility |
|---|---|
| Ingestion | Convert heterogeneous scanner output into a common schema |
| Schema | Enforce structured input/output contracts |
| Normalization | Map raw findings to canonical CWE taxonomy |
| Entity Extraction | Extract endpoint, parameter, package, version, file path, etc. |
| Embeddings / Retrieval | Detect duplicates and similar historical findings |
| Memory | Persist vulnerability history |
| Reachability | Estimate whether the vulnerable path is actually reachable |
| Threat Intelligence | Add exploit-likelihood context |
| Scoring | Produce explainable priority/risk score |
| Agent | Generate triage explanation and fix suggestion |
| WAF Gate | Decide whether WAF proposal is allowed |
| Policy | Enforce human approval requirements |
| Evaluation | Measure correctness, ranking, calibration, and safety |
| Audit / Feedback | Record decisions and use reviewer corrections for improvement |

The project avoids a common bad design:

```text
Raw finding → LLM → final decision
```

Instead, it uses a safer design:

```text
Raw finding
→ deterministic normalization/scoring/policy
→ LLM-assisted explanation
→ human approval for risky actions
```

This makes the system more explainable, testable, and safer.

---

## 4. Version-by-Version Journey Summary

| Version | Main Theme | Main Achievement |
|---|---|---|
| v1 | Local runnable MVP | End-to-end vulnerability triage pipeline without paid APIs |
| v2 | ML upgrade | Trainable CWE classifier, ML mode, persistent reports |
| v3 | Memory and LLM-ready architecture | SQLite vector memory, optional embeddings/vector DB/LLM hooks |
| v4 | Realistic AppSec workflow | Scanner adapters, vulnerable app, dashboard, Docker Compose |
| v5 | Senior ML maturity | Calibration, audit logs, feedback loop, threat intel, callgraph-style reachability |

---

# 5. v1 Journey — Rule-Based Runnable MVP

## 5.1 Purpose of v1

The purpose of v1 was to create the first working version of the system that could run locally without API keys, GPU, cloud services, or external scanner installations.

The main objective was:

```text
Build a complete end-to-end AppSec AI pipeline that proves the architecture.
```

v1 focused on system structure rather than advanced ML.

## 5.2 What v1 Implemented

v1 included:

- FastAPI backend
- CLI runner
- Pydantic canonical vulnerability schema
- Sample SAST, DAST, and SCA JSON findings
- Rule-based CWE normalization
- Regex/rule-based entity extraction
- Hash-based embedding similarity
- In-memory vulnerability deduplication
- Bayesian-style priority score
- Reachability gate
- WAF proposal safety gate
- Local deterministic triage agent
- Evaluation script
- Pytest smoke tests
- Dockerfile
- README and basic reports

## 5.3 Why v1 Was Designed This Way

The job requirement is large and senior-level. Starting with transformer models, vector databases, and LLM agents immediately would make the project difficult to run and debug.

So v1 used local deterministic logic first.

Design reason:

```text
First make the architecture runnable.
Then replace simple components with stronger ML/LLM systems later.
```

## 5.4 v1 Technical Stack

| Component | Tool/Method |
|---|---|
| Language | Python |
| API | FastAPI |
| Validation | Pydantic |
| Data | JSON fixtures |
| CWE Classification | Rule/keyword matching |
| Entity Extraction | Regex/rules |
| Embedding | Hash-based local vector |
| Similarity | Cosine similarity |
| Memory | In-memory store |
| Scoring | Confidence-weighted formula |
| Agent | Local deterministic triage logic |
| WAF Safety | Code-level rule gate |
| Testing | Pytest |
| Packaging | Dockerfile |

## 5.5 v1 Pipeline Flow

```text
sample_findings_all.json
    ↓
parse_generic_findings()
    ↓
VulnerabilityFinding schema
    ↓
classify_cwe()
    ↓
extract_entities()
    ↓
evaluate_reachability()
    ↓
memory.find_or_add()
    ↓
calculate_priority_score()
    ↓
build_waf_rule_proposal()
    ↓
local_triage_agent()
    ↓
TriageResult output
```

## 5.6 Important v1 Design Decision: WAF Safety Gate

The company requirement said:

```text
SAST-only signals must never trigger WAF rule generation.
```

v1 implemented this as deterministic code.

That is important because SAST findings can be false positives. A WAF rule based only on SAST output could block real users.

So v1 enforced:

```text
If source_type = SAST and DAST confirmation is missing:
    WAF rule is blocked.
```

## 5.7 What v1 Proved

v1 proved that the architecture works:

```text
Finding input
→ CWE output
→ risk score
→ duplicate status
→ triage decision
→ WAF safety decision
```

## 5.8 v1 Limitation

v1 was not real ML yet. It used rules and local heuristics.

Main limitations:

- No trainable classifier
- No persistent memory
- No real scanner adapters
- No dashboard
- No calibration
- No audit log
- No threat intelligence enrichment

---

# 6. v2 Journey — Trainable ML Classifier and Reporting

## 6.1 Purpose of v2

The purpose of v2 was to move from pure rule-based logic to a trainable ML approach.

v2 answered this job requirement:

```text
Design and train text classification models for vulnerability description normalization.
```

## 6.2 What v2 Implemented

v2 added:

- Trainable scikit-learn CWE classifier
- TF-IDF vectorization
- Logistic Regression classifier
- ML mode in CLI/API
- `--use-ml` flag
- Training dataset in JSONL format
- Saved model using Joblib
- Persistent vulnerability memory support
- Markdown batch report generation
- ML evaluation mode
- Updated README and design documentation

## 6.3 Why v2 Was Designed This Way

The job requires CWE normalization using NLP.

Instead of jumping directly to BERT/CodeBERT, v2 used a strong baseline:

```text
TF-IDF + Logistic Regression
```

This is a common and explainable NLP baseline.

It is useful because:

- It trains quickly.
- It runs on CPU.
- It is easy to debug.
- It gives probability outputs.
- It provides a baseline to compare future transformer models against.

## 6.4 v2 Technical Stack

| Component | Tool/Method |
|---|---|
| ML Library | scikit-learn |
| Text Features | TF-IDF |
| Classifier | Logistic Regression |
| Model Save | Joblib |
| Data Format | JSONL |
| Metrics | Accuracy / basic evaluation |
| Reports | Markdown report writer |
| CLI/API Mode | `--use-ml` flag |

## 6.5 v2 Model Method

The classifier learns from vulnerability descriptions.

Example training row:

```json
{
  "text": "User input reaches raw SQL query without sanitization",
  "label": "CWE-89"
}
```

The pipeline:

```text
description/title text
    ↓
TF-IDF vectorizer
    ↓
Logistic Regression classifier
    ↓
CWE prediction + confidence
```

## 6.6 v2 Commands

Train model:

```bash
python -m app.ml.train_cwe_classifier \
  --input data/cwe_training_findings.jsonl \
  --output models/cwe_tfidf_logreg.joblib \
  --metrics output/cwe_training_metrics.json
```

Run ML mode:

```bash
python -m app.cli \
  --input data/sample_findings_all.json \
  --use-ml \
  --pretty
```

Generate report:

```bash
python -m app.cli \
  --input data/sample_findings_all.json \
  --use-ml \
  --output output/results_ml.json \
  --report output/batch_report.md \
  --pretty
```

## 6.7 What v2 Proved

v2 proved:

- The architecture can use trained models.
- Rule-based CWE classification can be replaced without rewriting the pipeline.
- ML output can be evaluated and reported.
- The system can produce -ready batch reports.

## 6.8 v2 Limitation

v2 still had limitations:

- Small training dataset
- No transformer model
- No calibration metrics
- No real vector DB
- No scanner integration
- No dashboard
- No audit log or feedback loop

---

# 7. v3 Journey — Persistent Vector Memory and LLM-Ready Architecture

## 7.1 Purpose of v3

The purpose of v3 was to improve memory, deduplication, and agentic readiness.

v3 addressed these requirements:

```text
Hands-on experience with vector databases and embedding-based retrieval.
Persistent organizational vulnerability memory.
Agentic AI system design with human approval gates.
```

## 7.2 What v3 Implemented

v3 added:

- SQLite-backed persistent vector-style memory
- Embedding provider abstraction
- Optional Sentence-Transformers support
- Optional Chroma vector DB adapter
- Optional OpenAI LLM triage agent
- Safe local fallback when API key is missing
- Human approval action policy
- Human feedback API
- Improved batch report fields
- Docker Compose support
- Extra tests

## 7.3 Why v3 Was Designed This Way

Deduplication and memory are central to this job.

A vulnerability may appear multiple times:

```text
SAST: SQL injection in orders function
DAST: SQL injection at /api/orders?id=1
Previous scan: same endpoint flagged last week
```

The system needs to recognize that these may be related.

v3 introduced persistent memory so findings could be stored across runs.

## 7.4 v3 Technical Stack

| Component | Tool/Method |
|---|---|
| Persistent Memory | SQLite |
| Default Embedding | Hash embedding |
| Optional Embedding | Sentence-Transformers |
| Optional Vector Store | Chroma |
| Optional LLM | OpenAI structured triage |
| Agent Fallback | Local deterministic agent |
| Policy | Human approval logic |
| Deployment | Docker Compose |
| API | FastAPI |

## 7.5 v3 Memory Architecture

```text
Finding text
    ↓
Embedding provider
    ↓
Vector representation
    ↓
SQLite memory table
    ↓
Similarity comparison
    ↓
Duplicate group / similar finding result
```

## 7.6 Why SQLite First

SQLite was chosen for default persistent memory because:

- It runs locally.
- It requires no external server.
- It is easy for beginners.
- It can store findings and vectors.
- It makes the project immediately runnable.

Production upgrade path:

```text
SQLite → Chroma → Qdrant / pgvector / Pinecone
```

## 7.7 v3 LLM Design

The optional LLM agent was designed as an assistant, not the main decision maker.

Correct flow:

```text
Pipeline calculates facts.
LLM explains facts.
Policy gate approves or blocks actions.
```

Wrong flow avoided:

```text
LLM decides everything.
```

This matters because LLMs can hallucinate. A security system must not let an LLM bypass safety constraints.

## 7.8 v3 Commands

Run v3:

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

Optional advanced dependencies:

```bash
pip install -r requirements-advanced.txt
```

Optional LLM mode:

```bash
python -m app.cli \
  --input data/sample_findings_all.json \
  --use-ml \
  --use-llm \
  --memory-backend sqlite \
  --memory-file output/v3_memory.sqlite \
  --pretty
```

## 7.9 What v3 Proved

v3 proved:

- Vulnerability memory can persist across pipeline runs.
- Embedding provider can be swapped.
- Vector DB can be added later without changing the full pipeline.
- LLM triage can be added safely with fallback.
- Human approval can be enforced outside the prompt.

## 7.10 v3 Limitation

v3 still used sample findings. It did not yet connect to realistic scanner outputs or show a dashboard.

---

# 8. v4 Journey — Scanner Integration, Demo App, Dashboard

## 8.1 Purpose of v4

The purpose of v4 was to make the project more realistic from an AppSec workflow perspective.

v4 answered these job requirements:

```text
Familiarity with how SAST, DAST, and SCA tools produce findings.
Schema inconsistencies across tool categories.
Product goal of engineers completing triage workflows through interfaces.
```

## 8.2 What v4 Implemented

v4 added:

- Semgrep scanner adapter
- OWASP ZAP scanner adapter
- OWASP Dependency-Check adapter
- Offline scanner fixtures
- Demo vulnerable Flask app
- Streamlit dashboard
- Full benchmark command
- Docker Compose with API/dashboard/demo app
- API endpoints for scanner fixture triage
- Improved reports
- Expanded tests

## 8.3 Why v4 Was Designed This Way

Up to v3, the project used sample canonical findings.

But the job asks for scanner normalization.

So v4 introduced scanner-style input.

The new flow became:

```text
Semgrep / ZAP / Dependency-Check output
    ↓
scanner adapter
    ↓
canonical VulnerabilityFinding
    ↓
same AI pipeline from v3
```

This is important because it shows that the system can handle heterogeneous security tool outputs.

## 8.4 v4 Technical Stack

| Component | Tool/Method |
|---|---|
| SAST Adapter | Semgrep-style JSON |
| DAST Adapter | OWASP ZAP-style JSON |
| SCA Adapter | OWASP Dependency-Check-style JSON |
| Demo App | Flask |
| Dashboard | Streamlit |
| API | FastAPI |
| Containerization | Docker Compose |
| Benchmark | Python evaluation script |
| ML | TF-IDF + Logistic Regression |
| Memory | SQLite vector-style store |

## 8.5 Demo Vulnerable App

v4 included a vulnerable Flask app containing example weaknesses:

| Vulnerability | CWE |
|---|---|
| SQL Injection | CWE-89 |
| Reflected XSS | CWE-79 |
| Path Traversal | CWE-22 |
| Hardcoded Secret | CWE-798 |
| Vulnerable Dependency | SCA/CVE-style finding |

Purpose:

```text
Show an end-to-end AppSec AI demo from vulnerable app to scanner output to AI triage.
```

## 8.6 Scanner Adapters

The scanner adapters normalize different scanner schemas.

Example:

```text
Semgrep output → app/scanners/semgrep_adapter.py
ZAP output → app/scanners/zap_adapter.py
Dependency-Check output → app/scanners/dependency_check_adapter.py
```

Each adapter converts native-style output into the canonical schema.

## 8.7 Dashboard Purpose

The Streamlit dashboard was added to make the project easier to demonstrate visually.

Dashboard value:

- Shows total findings
- Shows severity/risk distribution
- Shows CWE mapping
- Shows duplicate groups
- Shows triage decision
- Shows WAF approval status
- Helps non-technical stakeholders understand the result

## 8.8 v4 Commands

Generate scanner findings:

```bash
python -m app.scanners.run_all --output output/scanner_findings_all.json
```

Run v4 AI pipeline:

```bash
python -m app.cli \
  --input output/scanner_findings_all.json \
  --use-ml \
  --memory-backend sqlite \
  --memory-file output/v4_memory.sqlite \
  --output output/v4_results.json \
  --report output/v4_report.md \
  --pretty
```

Run dashboard:

```bash
streamlit run app/dashboard/streamlit_app.py
```

Run Docker Compose:

```bash
docker compose up --build
```

## 8.9 What v4 Proved

v4 proved:

- The system can normalize SAST/DAST/SCA-style outputs.
- The same AI pipeline can process scanner-generated findings.
- A vulnerable app can be used for demo/testing.
- The project can be shown through dashboard and API.
- Docker Compose makes the demo more production-like.

## 8.10 v4 Limitation

v4 still needed more senior ML evidence:

- Calibration metrics
- Auditability
- Feedback loop
- Threat intelligence enrichment
- Reachability evidence beyond simple heuristics

---

# 9. v5 Journey — Calibration, Auditability, Feedback, Threat Intel, Reachability Evidence

## 9.1 Purpose of v5

The purpose of v5 was to close the senior-role gaps.

v5 focused on:

```text
calibration
auditability
feedback loops
threat intelligence
reachability evidence
MCP-style tool contracts
```

This version was designed to make the project stronger for a senior ML/AppSec AI.

## 9.2 What v5 Implemented

v5 added:

- CWE calibration metrics
- Accuracy, macro-F1, Brier score, Expected Calibration Error
- Confidence bins
- Threat-intelligence enrichment from local exploit-likelihood signals
- Callgraph-style reachability fixture
- Audit log with append-only JSONL records
- Feedback-to-training loop
- MCP-style tool contracts
- Combined v5 benchmark
- v5 architecture documentation
- Expanded tests

v5 kept all v4 features:

- Scanner adapters
- Demo vulnerable app
- Streamlit dashboard
- FastAPI API
- Docker Compose
- ML classifier
- SQLite memory
- WAF safety gate
- Reports

## 9.3 Why v5 Was Designed This Way

The original job requirement emphasized that scoring must be:

```text
calibrated, explainable, and auditable
```

Accuracy alone is not enough.

For example, if a model says:

```text
confidence = 0.90
```

then roughly 90% of those predictions should be correct. That is calibration.

v5 added calibration metrics to show this concept.

## 9.4 v5 Technical Stack

| Component | Tool/Method |
|---|---|
| Calibration | Brier score, Expected Calibration Error, confidence bins |
| Evaluation | Full benchmark + calibration benchmark |
| Audit | JSONL append-only decision log |
| Feedback | Reviewer corrections converted to training records |
| Threat Intel | Local exploit-likelihood JSON fixture |
| Reachability | Callgraph-style route/function fixture |
| MCP Prep | Local MCP-style tool contracts |
| ML Model | TF-IDF + Logistic Regression |
| API/Dashboard | FastAPI + Streamlit |
| Storage | SQLite memory |

## 9.5 v5 Calibration Method

v5 evaluates CWE classifier confidence.

Metrics:

| Metric | Meaning |
|---|---|
| Accuracy | How many predictions are correct |
| Macro-F1 | Balanced performance across CWE classes |
| Brier Score | Measures probability quality |
| ECE | Expected Calibration Error |
| Confidence Bins | Groups predictions by confidence range |

Example v5 calibration result from bundled data:

```json
{
  "accuracy": 1.0,
  "macro_f1": 1.0,
  "brier_score_multiclass": 0.4071,
  "expected_calibration_error": 0.5972,
  "mean_confidence": 0.4028
}
```

Important interpretation:

```text
The demo dataset is small, so high accuracy is not production evidence.
The calibration result shows the model is underconfident and needs better calibration/data.
```

That is exactly the type of honest ML analysis expected in senior roles.

## 9.6 v5 Threat Intelligence Enrichment

v5 added local threat intelligence signals.

Purpose:

```text
Risk should increase if exploit likelihood is higher.
```

Example signals:

- exploit available
- known exploitation pattern
- public-facing asset
- high-risk CWE
- threat condition triggers

These signals feed into scoring evidence.

## 9.7 v5 Callgraph-Style Reachability Fixture

v5 added `data/callgraph_routes.json`.

Purpose:

```text
Simulate CodeQL/Joern-style reachability evidence without heavy dependencies.
```

This helps show the integration contract:

```text
Finding endpoint/function
    ↓
callgraph fixture
    ↓
reachable true/false
    ↓
priority score adjustment
```

It is not full static analysis, but it demonstrates the correct architecture.

## 9.8 v5 Audit Log

v5 added append-only JSONL audit logs.

Purpose:

```text
Every triage decision should be inspectable later.
```

An audit record can include:

- finding ID
- source type
- CWE prediction
- confidence
- score
- risk level
- WAF decision
- human approval requirement
- timestamp-like run record
- evidence summary

This supports regulated/auditable AI requirements.

## 9.9 v5 Feedback-to-Training Loop

The feedback module supports reviewer corrections.

Example:

```text
Reviewer says:
Predicted CWE-79, but correct label is CWE-89.
```

The system can convert that into a new training example.

Purpose:

```text
Human decisions improve future model training.
```

This is important because the job mentioned feedback loops from human approval decisions.

## 9.10 v5 MCP-Style Tool Contracts

v5 introduced MCP-style local tool contracts.

Purpose:

```text
Prepare for future agent tools where LLM agents call approved system tools.
```

This does not implement a full MCP server, but it demonstrates the contract structure for future integration.

## 9.11 v5 Commands

Train model:

```bash
python -m app.ml.train_cwe_classifier \
  --input data/cwe_training_findings.jsonl \
  --output models/cwe_tfidf_logreg.joblib \
  --metrics output/cwe_training_metrics.json
```

Generate scanner findings:

```bash
python -m app.scanners.run_all \
  --output output/scanner_findings_all.json
```

Run v5 pipeline with audit logging:

```bash
python -m app.cli \
  --input output/scanner_findings_all.json \
  --use-ml \
  --memory-backend sqlite \
  --memory-file output/v5_memory.sqlite \
  --output output/v5_results_ml.json \
  --report output/v5_report_ml.md \
  --audit-log output/v5_audit_log.jsonl \
  --pretty
```

Run calibration report:

```bash
python -m app.evaluation.model_calibration \
  --input data/sample_findings_all.json \
  --labels data/eval_labeled_findings.json \
  --output output/v5_cwe_calibration_metrics.json \
  --report output/v5_cwe_calibration_report.md
```

Run combined benchmark:

```bash
python -m app.evaluation.full_benchmark_v5 \
  --use-ml \
  --output output/v5_full_benchmark_metrics.json \
  --report output/v5_full_benchmark_report.md
```

Run all v5 demo steps:

```bash
bash scripts/run_v5_demo.sh
```

Windows:

```bat
scripts\run_v5_demo.bat
```

## 9.12 What v5 Proved

v5 proves:

- The project understands model calibration.
- The system is moving toward auditability.
- Human feedback can improve training data.
- Threat intelligence can influence scoring.
- Reachability should be evidence-based.
- Agent tools should use contracts and policies.
- The project is no longer just a demo pipeline; it is a credible AppSec AI architecture prototype.

## 9.13 v5 Limitation

v5 is still not a production enterprise system.

Remaining gaps:

- Dataset is small.
- Transformer classifier is not fully trained.
- Real CodeQL/Joern reachability is not implemented.
- Chroma/Sentence-Transformers remain optional upgrade path.
- Full MCP server is not implemented.
- MLflow/drift monitoring is not fully implemented.
- Scanner integrations use offline fixtures by default.

---

# 10. Full Feature Evolution Table

| Feature | v1 | v2 | v3 | v4 | v5 |
|---|---|---|---|---|---|
| CLI runner | Yes | Yes | Yes | Yes | Yes |
| FastAPI | Yes | Yes | Yes | Yes | Yes |
| Canonical schema | Yes | Yes | Yes | Yes | Yes |
| Rule-based CWE | Yes | Yes | Yes | Yes | Yes |
| ML CWE classifier | No | Yes | Yes | Yes | Yes |
| TF-IDF | No | Yes | Yes | Yes | Yes |
| Logistic Regression | No | Yes | Yes | Yes | Yes |
| Entity extraction | Basic | Basic | Basic | Basic | Basic |
| Hash embeddings | Yes | Yes | Yes | Yes | Yes |
| Persistent memory | No/basic | Basic | SQLite | SQLite | SQLite |
| Optional Chroma | No | No | Yes | Yes | Yes |
| Optional Sentence-Transformers | No | No | Yes | Yes | Yes |
| Optional LLM | No | No | Yes | Yes | Yes |
| Human approval policy | Basic | Basic | Improved | Improved | Improved |
| WAF safety gate | Yes | Yes | Yes | Yes | Yes |
| Scanner adapters | No | No | No | Yes | Yes |
| Demo vulnerable app | No | No | No | Yes | Yes |
| Dashboard | No | No | No | Yes | Yes |
| Docker Compose | No | No | Yes | Yes | Yes |
| Full benchmark | Basic | Basic | Basic | Yes | Yes |
| Calibration metrics | No | No | No | No | Yes |
| Threat intel enrichment | No | No | No | No | Yes |
| Callgraph fixture | No | No | No | No | Yes |
| Audit log | No | No | No | No | Yes |
| Feedback training loop | No | No | Basic feedback API | Basic | Improved |
| MCP-style contracts | No | No | No | No | Yes |

---

# 11. Methodology Used in the Project

## 11.1 Canonical Schema Method

Problem:

```text
Different tools output different fields.
```

Method:

```text
Convert all tool outputs into one canonical VulnerabilityFinding schema.
```

Purpose:

- Reduces schema inconsistency
- Makes ML pipeline tool-independent
- Makes scoring and triage consistent

## 11.2 CWE Normalization Method

Problem:

```text
Raw finding text must be mapped to a standard weakness class.
```

Methods used:

- v1: rule-based keywords
- v2-v5: TF-IDF + Logistic Regression ML classifier
- Future: Transformer/CodeBERT classifier

Purpose:

- Standardize vulnerability meaning
- Support reporting and prioritization
- Connect scanner findings to CWE taxonomy

## 11.3 Entity Extraction Method

Problem:

```text
Developers need exact affected endpoint, parameter, file, package, and version.
```

Method:

- Regex/rule-based extraction

Purpose:

- Better fix suggestions
- Better deduplication
- Better WAF proposal context
- Better developer communication

## 11.4 Embedding/Deduplication Method

Problem:

```text
Same vulnerability may appear in multiple scanner outputs.
```

Method:

- Convert finding text into vector representation
- Compare using cosine similarity
- Add boosts for same CWE, asset, endpoint

Purpose:

- Reduce duplicate triage work
- Build organizational vulnerability memory
- Track recurring findings

## 11.5 Bayesian-Style Priority Scoring Method

Problem:

```text
CVSS alone is not enough for prioritization.
```

Method:

Use confidence-weighted scoring with evidence:

- CWE confidence
- CVSS
- source type
- reachability
- exploit availability
- asset exposure
- business criticality
- DAST confirmation
- duplicate status
- threat intelligence

Purpose:

```text
Produce explainable actionable priority.
```

## 11.6 Reachability Method

Problem:

```text
Not every finding is actually exploitable or reachable.
```

Methods:

- v1-v4: simple reachability rules
- v5: callgraph-style fixture

Purpose:

- Reduce false positives
- Improve prioritization
- Avoid overreacting to unreachable code

## 11.7 WAF Gate Method

Problem:

```text
Automatic WAF rule generation can break production traffic.
```

Method:

Hard-coded safety policy:

```text
SAST-only findings cannot generate WAF rules.
Human approval is required for WAF proposals.
```

Purpose:

- Prevent unsafe automated remediation
- Keep safety outside LLM prompt
- Match AppSec production constraints

## 11.8 Agentic Triage Method

Problem:

```text
Security teams and developers need readable triage explanation.
```

Method:

- Local deterministic agent by default
- Optional LLM agent with fallback
- Structured output and policy gates

Purpose:

- Generate fix suggestion
- Explain risk
- Support developer workflow
- Avoid giving LLM direct control over unsafe actions

## 11.9 Evaluation Method

Methods added over time:

- v1: smoke tests
- v2: ML evaluation
- v4: full benchmark
- v5: calibration metrics and combined benchmark

Metrics:

- Accuracy
- Macro-F1
- Priority rank accuracy
- WAF false positive rate
- Brier score
- Expected Calibration Error
- Confidence bins

Purpose:

```text
Make model behavior measurable, explainable, and auditable.
```

## 11.10 Feedback Loop Method

Problem:

```text
Models improve when human corrections are captured.
```

Method:

- Store reviewer feedback
- Convert corrected labels into training examples
- Use feedback for retraining

Purpose:

- Continuous improvement
- Human-in-the-loop ML
- Auditability

---

# 12. Complete Technology Stack

## 12.1 Core Backend

| Purpose | Technology |
|---|---|
| Language | Python |
| API | FastAPI |
| CLI | argparse / Python module execution |
| Validation | Pydantic |
| Reports | Markdown writer |
| Testing | Pytest |
| Packaging | Docker / Docker Compose |

## 12.2 ML/NLP

| Purpose | Technology |
|---|---|
| Baseline ML | scikit-learn |
| Text vectorization | TF-IDF |
| Classification | Logistic Regression |
| Model serialization | Joblib |
| Metrics | scikit-learn metrics |
| Calibration | Brier score / ECE logic |
| Future transformer path | Hugging Face / PyTorch / CodeBERT |

## 12.3 Embeddings and Memory

| Purpose | Technology |
|---|---|
| Default embedding | Hash embedding |
| Similarity | Cosine similarity |
| Persistent memory | SQLite |
| Optional vector DB | Chroma |
| Optional embedding model | Sentence-Transformers |

## 12.4 AppSec Tools

| Purpose | Tool |
|---|---|
| SAST fixture/adapter | Semgrep-style output |
| DAST fixture/adapter | OWASP ZAP-style output |
| SCA fixture/adapter | Dependency-Check-style output |
| Weakness taxonomy | CWE |
| Severity | CVSS-style signal |
| WAF logic | ModSecurity/OWASP CRS-style conceptual gate |

## 12.5 Agent and Governance

| Purpose | Technology/Method |
|---|---|
| Local triage | Deterministic agent |
| Optional LLM | OpenAI-compatible optional agent |
| Agent orchestration path | Agent graph abstraction |
| Human approval | Code-level action policy |
| MCP preparation | MCP-style tool contracts |
| Audit | JSONL log |
| Feedback | Feedback store + training data builder |

## 12.6 UI and Deployment

| Purpose | Technology |
|---|---|
| Dashboard | Streamlit |
| API docs | FastAPI Swagger UI |
| Demo app | Flask |
| Deployment demo | Docker Compose |

---

# 13. How Each Version Maps to the Job Requirements

| Job Requirement | Project Coverage |
|---|---|
| Python ML ecosystem | v1-v5 use Python, scikit-learn, ML pipeline |
| NLP classification | v2-v5 TF-IDF + Logistic Regression CWE classifier |
| Entity extraction | v1-v5 regex/rule entity extractor |
| CWE normalization | v1 rules, v2-v5 ML mode |
| Vector memory | v1 hash memory, v3-v5 SQLite vector-style memory |
| Deduplication | v1-v5 similarity grouping |
| Bayesian scoring | v1-v5 confidence-weighted priority scoring |
| Calibration | v5 Brier score, ECE, confidence bins |
| SAST/DAST/SCA schema normalization | v4-v5 scanner adapters |
| WAF logic | v1-v5 WAF safety gate |
| Reachability | v1-v4 simple gate, v5 callgraph-style fixture |
| Agentic AI | v3-v5 optional LLM/local agent architecture |
| Human approval | v1 basic, v3-v5 stronger policy |
| Evaluation | v1 basic, v4 full benchmark, v5 calibration benchmark |
| Auditability | v5 audit log |
| Feedback loops | v3 feedback API, v5 feedback-to-training loop |
| MCP | v5 MCP-style contracts |
| Dashboard/workflow | v4-v5 Streamlit dashboard |
| Docker deployment | v3-v5 Docker Compose |

---

# 14. Explanation Script

You can explain the project like this:

> I built this project as a staged AppSec AI system. In v1, I created a runnable end-to-end pipeline that accepted SAST/DAST/SCA-style findings, normalized them into a canonical schema, mapped them to CWE using rules, deduplicated them using lightweight embeddings, scored priority, and enforced a WAF safety gate.  
>
> In v2, I upgraded CWE normalization from rules to a trainable scikit-learn text classifier using TF-IDF and Logistic Regression. This made the system ML-driven while keeping it explainable and easy to evaluate.  
>
> In v3, I added persistent vector-style memory using SQLite, optional Sentence-Transformers/Chroma hooks, optional LLM triage, and a human approval policy. This turned the project into a memory-aware agentic triage architecture.  
>
> In v4, I added realistic AppSec workflow features: Semgrep, ZAP, and Dependency-Check adapters, scanner fixtures, a vulnerable Flask demo app, a Streamlit dashboard, Docker Compose, and a full benchmark.  
>
> In v5, I focused on senior ML requirements: calibration metrics such as Brier score and ECE, threat-intelligence enrichment, callgraph-style reachability evidence, audit logging, feedback-to-training conversion, and MCP-style tool contracts.  
>
> The key design decision is that LLMs never control unsafe actions directly. The LLM or local agent can explain and recommend, but WAF rule eligibility, human approval, and action policy are enforced by deterministic code.

---

# 15. What the Project Demonstrates Well

The project strongly demonstrates:

- Understanding of AppSec AI architecture
- Scanner schema normalization
- CWE normalization logic
- ML baseline design
- Deduplication using vector-style memory
- Explainable scoring
- WAF safety constraints
- Human-in-the-loop design
- API + CLI + dashboard delivery
- Evaluation mindset
- Calibration awareness
- Auditability awareness
- Portfolio-quality system thinking

---

# 16. What the Project Does Not Fully Prove Yet

The project is still a prototype.

It does not fully prove:

- 5+ years of production ML experience
- Real large-scale training data handling
- Fine-tuned transformer model performance
- Real CodeQL/Joern reachability analysis
- Real live ZAP/Semgrep/Dependency-Check orchestration at enterprise scale
- Production-grade vector database operations
- Full MCP server implementation
- Full MLflow model registry/drift monitoring
- Real regulated-industry audit process
- Production WAF deployment workflow

---

# 17. Recommended v6 Roadmap

To move beyond v5, build v6 with:

1. Fine-tuned transformer CWE classifier  
2. Real Sentence-Transformers embeddings by default  
3. Chroma or Qdrant as the default vector store  
4. Real Semgrep scan execution against the demo app  
5. Real OWASP ZAP baseline scan execution  
6. CodeQL or Joern reachability integration  
7. MLflow experiment tracking  
8. Drift detection report  
9. LangGraph-based multi-step agent  
10. Real MCP server implementation  
11. CI pipeline with benchmark threshold gates  
12. Larger labeled CWE dataset  
13. Reliability curve plot generation  
14. Security engineer/developer/board-level report templates  

---

# 18. Final Project Positioning

The project from v1 to v5 should be positioned as:

```text
A portfolio-grade AppSec AI vulnerability intelligence prototype.
```

It is not yet:

```text
A production enterprise vulnerability management platform.
```

The strongest way to present it is:

> This project demonstrates the architecture, workflow, and ML/AppSec reasoning behind a vulnerability intelligence system. It includes runnable modules for scanner normalization, CWE classification, deduplication, scoring, triage, WAF safety gating, dashboarding, calibration, audit logging, and feedback loops. The current implementation uses lightweight ML and local fixtures so it can run easily, while the architecture is designed for future upgrades to transformer models, real vector databases, CodeQL/Joern reachability, LangGraph agents, MCP tools, and production MLOps.

---

# 19. One-Line Summary for Resume or GitHub

**Vulnerability AI Triage Lab:** Built a staged AppSec AI prototype that ingests SAST/DAST/SCA findings, normalizes them into CWE taxonomy using ML, deduplicates similar issues with vector-style memory, scores risk with explainable evidence, generates triage/fix recommendations, enforces WAF/human-approval safety gates, and adds calibration, audit logging, feedback loops, scanner adapters, dashboard, and Dockerized demo deployment.

---

# 20. Short Version for LinkedIn

I built a five-stage AppSec AI portfolio project called **Vulnerability AI Triage Lab**. It evolved from a local rule-based MVP into a scanner-integrated, ML-assisted vulnerability intelligence prototype with CWE normalization, vector-style deduplication, Bayesian-style priority scoring, optional LLM triage, WAF safety gates, human approval policy, Streamlit dashboard, Docker Compose, calibration metrics, audit logs, threat-intelligence enrichment, reachability evidence, and feedback-to-training loops.

The key design principle: **LLMs assist and explain; deterministic system policies control risky security actions.**
