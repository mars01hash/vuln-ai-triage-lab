from __future__ import annotations

from app.schemas import AssetExposure, BusinessCriticality, SourceType, VulnerabilityFinding


def parse_generic_findings(payload: list[dict]) -> list[VulnerabilityFinding]:
    """Parse already-normal-ish JSON into VulnerabilityFinding objects.

    This keeps the MVP simple. Later, add dedicated Semgrep/ZAP/Dependency-Check
    adapters that map native tool schemas into this canonical input schema.
    """
    findings: list[VulnerabilityFinding] = []
    for item in payload:
        findings.append(VulnerabilityFinding(
            finding_id=str(item.get("finding_id") or item.get("id")),
            source_type=SourceType(item.get("source_type", "MANUAL")),
            tool_name=item.get("tool_name", "unknown"),
            title=item.get("title", "Untitled finding"),
            description=item.get("description", ""),
            cwe=item.get("cwe"),
            cvss=float(item.get("cvss", 5.0)),
            asset=item.get("asset", "unknown-asset"),
            endpoint=item.get("endpoint"),
            parameter=item.get("parameter"),
            file_path=item.get("file_path"),
            package=item.get("package"),
            version=item.get("version"),
            reachable=item.get("reachable"),
            exploit_available=bool(item.get("exploit_available", False)),
            business_criticality=BusinessCriticality(item.get("business_criticality", "medium")),
            asset_exposure=AssetExposure(item.get("asset_exposure", "internal")),
            dast_confirmed=bool(item.get("dast_confirmed", False)),
            raw=item,
        ))
    return findings
