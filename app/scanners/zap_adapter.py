from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from app.scanners.common import cwe_to_string, zap_risk_to_cvss
from app.schemas import AssetExposure, BusinessCriticality, SourceType, VulnerabilityFinding


def _extract_alerts(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if "site" in payload:
        alerts: list[dict[str, Any]] = []
        for site in payload.get("site", []):
            alerts.extend(site.get("alerts", []) or [])
        return alerts
    if "alerts" in payload:
        return payload.get("alerts", []) or []
    return []


def _extract_endpoint(alert: dict[str, Any]) -> str | None:
    instances = alert.get("instances") or []
    if instances:
        uri = instances[0].get("uri") or instances[0].get("url")
        if uri:
            return urlparse(uri).path or uri
    uri = alert.get("url") or alert.get("uri")
    return urlparse(uri).path if uri else None


def _extract_parameter(alert: dict[str, Any]) -> str | None:
    instances = alert.get("instances") or []
    if instances:
        param = instances[0].get("param")
        if param:
            return param
    return alert.get("param")


def parse_zap_results(payload: dict[str, Any], asset: str = "demo-vulnerable-app") -> list[VulnerabilityFinding]:
    """Map OWASP ZAP JSON report/API alerts into canonical findings."""
    findings: list[VulnerabilityFinding] = []
    for index, alert in enumerate(_extract_alerts(payload), start=1):
        title = alert.get("alert") or alert.get("name") or "ZAP alert"
        risk = alert.get("riskdesc") or alert.get("risk")
        desc = " ".join(str(x) for x in [title, alert.get("desc"), alert.get("evidence"), alert.get("solution")] if x)
        findings.append(
            VulnerabilityFinding(
                finding_id=f"ZAP-{index:03d}",
                source_type=SourceType.DAST,
                tool_name="OWASP ZAP",
                title=str(title),
                description=desc,
                cwe=cwe_to_string(alert.get("cweid") or alert.get("cwe")),
                cvss=zap_risk_to_cvss(risk),
                asset=asset,
                endpoint=_extract_endpoint(alert),
                parameter=_extract_parameter(alert),
                reachable=True,
                exploit_available=False,
                business_criticality=BusinessCriticality.high,
                asset_exposure=AssetExposure.internet,
                dast_confirmed=True,
                raw=alert,
            )
        )
    return findings
