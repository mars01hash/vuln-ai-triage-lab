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
