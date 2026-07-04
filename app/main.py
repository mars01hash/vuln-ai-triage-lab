from __future__ import annotations

from fastapi import FastAPI

from app.pipeline import TriagePipeline
from app.schemas import NormalizedFinding, VulnerabilityFinding

app = FastAPI(
    title="Vuln AI Triage Lab",
    description="Runnable MVP for AI-assisted vulnerability triage and CWE normalization.",
    version="0.1.0",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/triage", response_model=list[NormalizedFinding])
def triage(findings: list[VulnerabilityFinding]) -> list[NormalizedFinding]:
    # Create memory per request for deterministic API behavior.
    # In production, use persistent memory: Chroma/Qdrant/Postgres pgvector.
    pipeline = TriagePipeline()
    return pipeline.process_many(findings)
