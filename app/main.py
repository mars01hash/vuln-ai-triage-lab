from __future__ import annotations

from fastapi import FastAPI, Query

from app.feedback.feedback_store import FeedbackStore
from app.mcp.tool_contracts import list_tool_contracts
from app.pipeline import TriagePipeline
from app.scanners.common import read_json
from app.scanners.dependency_check_adapter import parse_dependency_check_results
from app.scanners.semgrep_adapter import parse_semgrep_results
from app.scanners.zap_adapter import parse_zap_results
from app.schemas import NormalizedFinding, TriageFeedback, VulnerabilityFinding
from app.storage.sqlite_vector_memory import SqliteVulnerabilityMemory

app = FastAPI(
    title="Vulnerability AI Triage Lab",
    version="5.0.0",
    description="v5 AppSec AI pipeline with scanner adapters, ML CWE normalization, vector-style memory, optional LLM triage, feedback logging, benchmark support, and WAF policy gates.",
)

# Persistent local vector memory for the API process.
api_memory = SqliteVulnerabilityMemory(db_path="output/api_vulnerability_memory.sqlite")
feedback_store = FeedbackStore(path="output/api_human_feedback.jsonl")


def _build_pipeline(use_ml: bool, use_llm: bool, llm_model: str) -> TriagePipeline:
    return TriagePipeline(
        memory=api_memory,
        use_ml_classifier=use_ml,
        use_llm_agent=use_llm,
        llm_model=llm_model,
        memory_backend_name="sqlite_vector_memory",
    )


@app.get("/")
def root() -> dict[str, str]:
    return {
        "name": "vuln-ai-triage-lab",
        "version": "5.0.0",
        "docs": "/docs",
        "message": "Use POST /triage, /triage/batch, or /demo/scanner-fixtures/triage. Optional flags: ?use_ml=true&use_llm=true",
    }


@app.post("/triage", response_model=NormalizedFinding)
def triage_one(
    finding: VulnerabilityFinding,
    use_ml: bool = Query(default=False, description="Use trained scikit-learn CWE classifier"),
    use_llm: bool = Query(default=False, description="Use optional LLM triage agent. Falls back locally if unavailable."),
    llm_model: str = Query(default="gpt-4o-mini", description="LLM model name for optional OpenAI triage"),
) -> NormalizedFinding:
    return _build_pipeline(use_ml, use_llm, llm_model).process_one(finding)


@app.post("/triage/batch", response_model=list[NormalizedFinding])
def triage_batch(
    findings: list[VulnerabilityFinding],
    use_ml: bool = Query(default=False, description="Use trained scikit-learn CWE classifier"),
    use_llm: bool = Query(default=False, description="Use optional LLM triage agent. Falls back locally if unavailable."),
    llm_model: str = Query(default="gpt-4o-mini", description="LLM model name for optional OpenAI triage"),
) -> list[NormalizedFinding]:
    return _build_pipeline(use_ml, use_llm, llm_model).process_many(findings)


@app.get("/demo/scanner-fixtures")
def scanner_fixture_findings() -> list[dict]:
    """Return bundled scanner fixture findings converted into canonical input JSON."""
    findings = []
    findings.extend(parse_semgrep_results(read_json("data/scanner_fixtures/semgrep_results.json")))
    findings.extend(parse_zap_results(read_json("data/scanner_fixtures/zap_report.json")))
    findings.extend(parse_dependency_check_results(read_json("data/scanner_fixtures/dependency_check_report.json")))
    return [finding.model_dump(mode="json") for finding in findings]


@app.post("/demo/scanner-fixtures/triage", response_model=list[NormalizedFinding])
def triage_scanner_fixtures(
    use_ml: bool = Query(default=False, description="Use trained scikit-learn CWE classifier"),
    use_llm: bool = Query(default=False, description="Use optional LLM triage agent. Falls back locally if unavailable."),
    llm_model: str = Query(default="gpt-4o-mini", description="LLM model name for optional OpenAI triage"),
) -> list[NormalizedFinding]:
    findings = []
    findings.extend(parse_semgrep_results(read_json("data/scanner_fixtures/semgrep_results.json")))
    findings.extend(parse_zap_results(read_json("data/scanner_fixtures/zap_report.json")))
    findings.extend(parse_dependency_check_results(read_json("data/scanner_fixtures/dependency_check_report.json")))
    return _build_pipeline(use_ml, use_llm, llm_model).process_many(findings)


@app.get("/memory/summary")
def memory_summary() -> dict[str, int | str]:
    return api_memory.summary()


@app.post("/feedback")
def add_feedback(feedback: TriageFeedback) -> dict[str, object]:
    return feedback_store.add(feedback)


@app.get("/feedback/summary")
def feedback_summary() -> dict[str, object]:
    return feedback_store.summary()


@app.get("/mcp/tool-contracts")
def mcp_tool_contracts() -> list[dict]:
    """Return local MCP-style tool contracts for agent/tool integration demos."""
    return list_tool_contracts()
