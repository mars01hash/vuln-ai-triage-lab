from __future__ import annotations

from fastapi import FastAPI, Query

from app.pipeline import TriagePipeline
from app.schemas import NormalizedFinding, VulnerabilityFinding
from app.storage.memory_store import VulnerabilityMemory

app = FastAPI(
    title="Vulnerability AI Triage Lab",
    version="2.0.0",
    description="MVP AppSec AI pipeline for CWE normalization, deduplication, scoring, triage, and WAF proposal gating.",
)

# Shared memory for API process lifetime. For persistence, use CLI --memory-file or add DB in production.
api_memory = VulnerabilityMemory()


@app.get("/")
def root() -> dict[str, str]:
    return {
        "name": "vuln-ai-triage-lab",
        "version": "2.0.0",
        "docs": "/docs",
        "message": "Use POST /triage or /triage/batch. Add ?use_ml=true after training the model.",
    }


@app.post("/triage", response_model=NormalizedFinding)
def triage_one(
    finding: VulnerabilityFinding,
    use_ml: bool = Query(default=False, description="Use trained scikit-learn CWE classifier"),
) -> NormalizedFinding:
    pipeline = TriagePipeline(memory=api_memory, use_ml_classifier=use_ml)
    return pipeline.process_one(finding)


@app.post("/triage/batch", response_model=list[NormalizedFinding])
def triage_batch(
    findings: list[VulnerabilityFinding],
    use_ml: bool = Query(default=False, description="Use trained scikit-learn CWE classifier"),
) -> list[NormalizedFinding]:
    pipeline = TriagePipeline(memory=api_memory, use_ml_classifier=use_ml)
    return pipeline.process_many(findings)


@app.get("/memory/summary")
def memory_summary() -> dict[str, int]:
    return api_memory.summary()
