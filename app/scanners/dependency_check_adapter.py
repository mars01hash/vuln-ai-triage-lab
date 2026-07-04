from __future__ import annotations

from typing import Any

from app.scanners.common import cwe_to_string, severity_to_cvss
from app.schemas import AssetExposure, BusinessCriticality, SourceType, VulnerabilityFinding


def _first_cwe(vuln: dict[str, Any]) -> str | None:
    cwes = vuln.get("cwes") or vuln.get("cwe")
    if isinstance(cwes, list) and cwes:
        return cwe_to_string(cwes[0])
    return cwe_to_string(cwes)


def parse_dependency_check_results(payload: dict[str, Any], asset: str = "demo-vulnerable-app") -> list[VulnerabilityFinding]:
    """Map OWASP Dependency-Check JSON into canonical SCA findings."""
    findings: list[VulnerabilityFinding] = []
    dependencies = payload.get("dependencies", []) if isinstance(payload, dict) else []
    counter = 1
    for dependency in dependencies:
        vulns = dependency.get("vulnerabilities", []) or []
        package = dependency.get("fileName") or dependency.get("filePath") or dependency.get("packageName") or "unknown-package"
        version = dependency.get("version") or dependency.get("evidenceCollected", {}).get("versionEvidence", [{}])[0].get("value")
        for vuln in vulns:
            cve = vuln.get("name") or vuln.get("source") or "Known vulnerable dependency"
            severity = vuln.get("severity") or vuln.get("cvssv3", {}).get("baseSeverity")
            cvss = vuln.get("cvssv3", {}).get("baseScore") or vuln.get("cvssv2", {}).get("score") or severity_to_cvss(severity, 7.0)
            description = " ".join(str(x) for x in [cve, vuln.get("description"), package, version] if x)
            findings.append(
                VulnerabilityFinding(
                    finding_id=f"DEPCHK-{counter:03d}",
                    source_type=SourceType.SCA,
                    tool_name="OWASP Dependency-Check",
                    title=str(cve),
                    description=description,
                    cwe=_first_cwe(vuln),
                    cvss=float(cvss),
                    asset=asset,
                    package=str(package),
                    version=str(version) if version else None,
                    reachable=None,
                    exploit_available=bool(vuln.get("knownExploited", False) or vuln.get("exploit_available", False)),
                    business_criticality=BusinessCriticality.medium,
                    asset_exposure=AssetExposure.internet,
                    dast_confirmed=False,
                    raw={"dependency": dependency, "vulnerability": vuln},
                )
            )
            counter += 1
    return findings
