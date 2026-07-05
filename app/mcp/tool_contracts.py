from __future__ import annotations

from typing import Any

from app.normalization.cwe_classifier import classify_cwe
from app.schemas import VulnerabilityFinding
from app.threat_intel.enrichment import enrich_finding_with_threat_intel


MCP_TOOL_CONTRACTS: list[dict[str, Any]] = [
    {
        "name": "normalize_vulnerability_to_cwe",
        "description": "Map a canonical vulnerability finding to a CWE label with confidence and evidence.",
        "input_schema": {"type": "object", "properties": {"finding": {"type": "object"}}, "required": ["finding"]},
        "output_schema": {"type": "object", "properties": {"cwe": {"type": "string"}, "confidence": {"type": "number"}, "evidence": {"type": "array"}}},
    },
    {
        "name": "enrich_with_threat_intel",
        "description": "Attach local threat-intelligence signals used by the scoring layer.",
        "input_schema": {"type": "object", "properties": {"finding": {"type": "object"}, "canonical_cwe": {"type": "string"}}, "required": ["finding", "canonical_cwe"]},
        "output_schema": {"type": "object", "properties": {"exploit_likelihood": {"type": "number"}, "exploited_in_wild": {"type": "boolean"}, "reason": {"type": "string"}}},
    },
]


def normalize_vulnerability_to_cwe(finding_payload: dict[str, Any]) -> dict[str, Any]:
    finding = VulnerabilityFinding.model_validate(finding_payload)
    cwe, name, confidence, evidence = classify_cwe(finding)
    return {"cwe": cwe, "cwe_name": name, "confidence": confidence, "evidence": evidence}


def enrich_with_threat_intel(finding_payload: dict[str, Any], canonical_cwe: str) -> dict[str, Any]:
    finding = VulnerabilityFinding.model_validate(finding_payload)
    return enrich_finding_with_threat_intel(finding, canonical_cwe)


def list_tool_contracts() -> list[dict[str, Any]]:
    return MCP_TOOL_CONTRACTS
