from app.scanners.common import read_json
from app.scanners.dependency_check_adapter import parse_dependency_check_results
from app.scanners.semgrep_adapter import parse_semgrep_results
from app.scanners.zap_adapter import parse_zap_results
from app.evaluation.full_benchmark import run_benchmark
from app.ingestion.adapters import parse_generic_findings
from app.pipeline import TriagePipeline


def test_semgrep_fixture_adapter_parses_canonical_findings():
    findings = parse_semgrep_results(read_json("data/scanner_fixtures/semgrep_results.json"))
    assert len(findings) == 4
    assert findings[0].source_type.value == "SAST"
    assert findings[0].cwe == "CWE-89"
    assert findings[0].endpoint == "/user"


def test_zap_fixture_adapter_marks_dast_confirmed_and_reachable():
    findings = parse_zap_results(read_json("data/scanner_fixtures/zap_report.json"))
    assert len(findings) == 3
    assert findings[0].source_type.value == "DAST"
    assert findings[0].dast_confirmed is True
    assert findings[0].reachable is True
    assert findings[0].cwe == "CWE-89"


def test_dependency_check_fixture_adapter_parses_sca_findings():
    findings = parse_dependency_check_results(read_json("data/scanner_fixtures/dependency_check_report.json"))
    assert len(findings) == 2
    assert findings[0].source_type.value == "SCA"
    assert findings[0].package == "jinja2==2.10"


def test_scanner_fixtures_flow_into_pipeline():
    semgrep = parse_semgrep_results(read_json("data/scanner_fixtures/semgrep_results.json"))
    zap = parse_zap_results(read_json("data/scanner_fixtures/zap_report.json"))
    dep = parse_dependency_check_results(read_json("data/scanner_fixtures/dependency_check_report.json"))
    payload = [f.model_dump(mode="json") for f in semgrep + zap + dep]
    results = TriagePipeline().process_many(parse_generic_findings(payload))
    assert len(results) == 9
    assert any(r.canonical_cwe == "CWE-89" for r in results)
    assert any(r.waf_rule_allowed for r in results if r.source_type.value == "DAST")


def test_full_benchmark_runs(tmp_path):
    metrics = run_benchmark(
        use_ml=False,
        output=str(tmp_path / "metrics.json"),
        report=str(tmp_path / "report.md"),
    )
    assert metrics["total_findings"] == 9
    assert metrics["cwe_accuracy"] >= 0.7
    assert metrics["waf_false_positive_rate"] <= 0.34
