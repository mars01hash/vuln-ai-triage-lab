# v3 Architecture Design

## Purpose

Version 3 upgrades the project from a trainable ML MVP into a more realistic AppSec AI service with persistent vector-style memory, optional LLM triage, and human feedback capture.

## Why SQLite vector memory?

A production system would likely use Qdrant, Chroma, FAISS, pgvector, or a managed vector database. For this portfolio version, SQLite gives three benefits:

1. It is persistent.
2. It requires no external server.
3. It demonstrates the vector-memory contract clearly.

Embeddings are stored as JSON vectors and compared using cosine similarity. The implementation can later be swapped for Chroma/Qdrant without changing the main pipeline.

## Why optional LLM?

The system must run without paid APIs, so local deterministic triage remains the default. The optional OpenAI agent is used only for triage explanation and fix recommendation text. It cannot override CWE classification, priority score, WAF gate, or approval rules.

## Safety Model

Dangerous decisions are not prompt-controlled:

- SAST-only findings cannot generate WAF proposals.
- WAF proposals always require human approval.
- High/critical issues require remediation review.
- LLM failure falls back to deterministic local triage.

## Upgrade Path

1. Replace hash embeddings with Sentence-Transformers or BGE.
2. Replace SQLite with Chroma, Qdrant, pgvector, or FAISS.
3. Replace TF-IDF classifier with CodeBERT/DeBERTa fine-tuning.
4. Add real scanner adapters for Semgrep, ZAP, Dependency-Check, Snyk, GitHub Code Scanning, and SARIF.
5. Add calibration metrics such as Brier score and expected calibration error.
6. Add model and prompt evaluation datasets from historical triage records.
