from __future__ import annotations

from fastapi import FastAPI, Query

from app.feedback.feedback_store import FeedbackStore
from app.pipeline import TriagePipeline
from app.schemas import NormalizedFinding, TriageFeedback, VulnerabilityFinding
from app.storage.sqlite_vector_memory import SqliteVulnerabilityMemory

app = FastAPI(
    title="Vulnerability AI Triage Lab",
    version="3.0.0",
    description="AppSec AI pipeline with ML CWE normalization, SQLite vector memory, optional LLM triage, feedback logging, scoring, and WAF policy gates.",
)

# Persistent local vector memory for the API process.
api_memory = SqliteVulnerabilityMemory(db_path="output/api_vulnerability_memory.sqlite")
feedback_store = FeedbackStore(path="output/api_human_feedback.jsonl")


@app.get("/")
def root() -> dict[str, str]:
    return {
        "name": "vuln-ai-triage-lab",
        "version": "3.0.0",
        "docs": "/docs",
        "message": "Use POST /triage or /triage/batch. Optional flags: ?use_ml=true&use_llm=true",
    }


@app.post("/triage", response_model=NormalizedFinding)
def triage_one(
    finding: VulnerabilityFinding,
    use_ml: bool = Query(default=False, description="Use trained scikit-learn CWE classifier"),
    use_llm: bool = Query(default=False, description="Use optional LLM triage agent. Falls back locally if unavailable."),
    llm_model: str = Query(default="gpt-4o-mini", description="LLM model name for optional OpenAI triage"),
) -> NormalizedFinding:
    pipeline = TriagePipeline(
        memory=api_memory,
        use_ml_classifier=use_ml,
        use_llm_agent=use_llm,
        llm_model=llm_model,
        memory_backend_name="sqlite_vector_memory",
    )
    return pipeline.process_one(finding)


@app.post("/triage/batch", response_model=list[NormalizedFinding])
def triage_batch(
    findings: list[VulnerabilityFinding],
    use_ml: bool = Query(default=False, description="Use trained scikit-learn CWE classifier"),
    use_llm: bool = Query(default=False, description="Use optional LLM triage agent. Falls back locally if unavailable."),
    llm_model: str = Query(default="gpt-4o-mini", description="LLM model name for optional OpenAI triage"),
) -> list[NormalizedFinding]:
    pipeline = TriagePipeline(
        memory=api_memory,
        use_ml_classifier=use_ml,
        use_llm_agent=use_llm,
        llm_model=llm_model,
        memory_backend_name="sqlite_vector_memory",
    )
    return pipeline.process_many(findings)


@app.get("/memory/summary")
def memory_summary() -> dict[str, int | str]:
    return api_memory.summary()


@app.post("/feedback")
def add_feedback(feedback: TriageFeedback) -> dict[str, object]:
    return feedback_store.add(feedback)


@app.get("/feedback/summary")
def feedback_summary() -> dict[str, object]:
    return feedback_store.summary()
