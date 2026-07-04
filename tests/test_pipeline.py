from app.pipeline import TriagePipeline
from app.schemas import SourceType, VulnerabilityFinding


def test_sql_injection_maps_to_cwe_89():
    finding = VulnerabilityFinding(
        finding_id="T-001",
        source_type=SourceType.SAST,
        tool_name="Semgrep",
        title="Possible SQL Injection",
        description="Unsanitized input reaches raw SQL query",
        cvss=8.8,
        endpoint="/api/orders",
        parameter="id",
        reachable=True,
        business_criticality="high",
        asset_exposure="internet",
        exploit_available=True,
    )
    result = TriagePipeline().process_one(finding)
    assert result.canonical_cwe == "CWE-89"
    assert result.risk_level in {"high", "critical"}


def test_sast_only_cannot_generate_waf_rule():
    finding = VulnerabilityFinding(
        finding_id="T-002",
        source_type=SourceType.SAST,
        tool_name="Semgrep",
        title="SQL Injection",
        description="sql injection in id parameter",
        cvss=9.0,
        endpoint="/api/orders",
        parameter="id",
        reachable=True,
        business_criticality="critical",
        asset_exposure="internet",
        exploit_available=True,
    )
    result = TriagePipeline().process_one(finding)
    assert result.waf_rule_allowed is False
    assert result.proposed_waf_rule is None


def test_dast_high_risk_can_propose_waf_rule():
    finding = VulnerabilityFinding(
        finding_id="T-003",
        source_type=SourceType.DAST,
        tool_name="OWASP ZAP",
        title="SQL Injection",
        description="SQL error detected from parameter id on /api/orders",
        cvss=9.0,
        endpoint="/api/orders",
        parameter="id",
        reachable=True,
        business_criticality="critical",
        asset_exposure="internet",
        exploit_available=True,
    )
    result = TriagePipeline().process_one(finding)
    assert result.waf_rule_allowed is True
    assert result.proposed_waf_rule is not None
    assert result.human_approval_required is True


def test_sqlite_memory_detects_duplicate(tmp_path):
    from app.storage.sqlite_vector_memory import SqliteVulnerabilityMemory

    memory = SqliteVulnerabilityMemory(db_path=tmp_path / "memory.sqlite", similarity_threshold=0.70)
    pipeline = TriagePipeline(memory=memory, memory_backend_name="sqlite_vector_memory")

    first = VulnerabilityFinding(
        finding_id="DUP-001",
        source_type=SourceType.DAST,
        tool_name="OWASP ZAP",
        title="SQL Injection",
        description="SQL error from id parameter on orders endpoint",
        cvss=8.8,
        asset="payment-api",
        endpoint="/api/orders",
        parameter="id",
        reachable=True,
        business_criticality="critical",
        asset_exposure="internet",
    )
    second = first.model_copy(update={
        "finding_id": "DUP-002",
        "description": "Union select payload works against id parameter in /api/orders",
    })

    first_result = pipeline.process_one(first)
    second_result = pipeline.process_one(second)

    assert first_result.duplicate_of is None
    assert second_result.duplicate_of == "DUP-001"
    assert second_result.memory_backend == "sqlite_vector_memory"


def test_llm_mode_falls_back_without_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    finding = VulnerabilityFinding(
        finding_id="LLM-001",
        source_type=SourceType.DAST,
        tool_name="OWASP ZAP",
        title="Reflected XSS",
        description="script execution in q parameter",
        cvss=7.1,
        endpoint="/search",
        parameter="q",
        reachable=True,
        business_criticality="high",
        asset_exposure="internet",
    )
    result = TriagePipeline(use_llm_agent=True).process_one(finding)
    assert result.agent_mode in {"local_fallback_after_llm_error", "local_rules"}
    assert result.recommended_fix
