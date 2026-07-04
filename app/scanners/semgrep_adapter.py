from __future__ import annotations

from typing import Any

from app.scanners.common import cwe_to_string, severity_to_cvss
from app.schemas import AssetExposure, BusinessCriticality, SourceType, VulnerabilityFinding


def _extract_cwe(extra: dict[str, Any]) -> str | None:
    metadata = extra.get("metadata") or {}
    cwe = metadata.get("cwe") or metadata.get("cwe_id") or metadata.get("cwe-id")
    if isinstance(cwe, list) and cwe:
        cwe = cwe[0]
    if isinstance(cwe, str) and "CWE-" in cwe.upper():
        import re
        match = re.search(r"CWE-?\s*(\d+)", cwe, flags=re.I)
        if match:
            return f"CWE-{match.group(1)}"
    return cwe_to_string(cwe)


def parse_semgrep_results(payload: dict[str, Any], asset: str = "demo-vulnerable-app") -> list[VulnerabilityFinding]:
    """Map Semgrep JSON output into canonical VulnerabilityFinding objects."""
    results = payload.get("results", []) if isinstance(payload, dict) else []
    findings: list[VulnerabilityFinding] = []
    for index, item in enumerate(results, start=1):
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        message = extra.get("message") or item.get("check_id") or "Semgrep finding"
        severity = extra.get("severity") or metadata.get("impact")
        finding_id = f"SEMGREP-{index:03d}"
        cwe = _extract_cwe(extra)
        path = item.get("path")
        start_line = (item.get("start") or {}).get("line")
        description = message
        if path:
            description += f" File: {path}"
        if start_line:
            description += f" Line: {start_line}"
        findings.append(
            VulnerabilityFinding(
                finding_id=finding_id,
                source_type=SourceType.SAST,
                tool_name="Semgrep",
                title=str(item.get("check_id") or message),
                description=description,
                cwe=cwe,
                cvss=severity_to_cvss(severity, default=6.5),
                asset=asset,
                endpoint=metadata.get("endpoint"),
                parameter=metadata.get("parameter"),
                file_path=path,
                reachable=None,
                exploit_available=bool(metadata.get("exploit_available", False)),
                business_criticality=BusinessCriticality.high if "sql" in message.lower() else BusinessCriticality.medium,
                asset_exposure=AssetExposure.internet,
                dast_confirmed=False,
                raw=item,
            )
        )
    return findings


def findings_to_json(findings: list[VulnerabilityFinding]) -> list[dict[str, Any]]:
    return [finding.model_dump(mode="json") for finding in findings]
