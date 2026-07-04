from __future__ import annotations

import re
from app.schemas import EntityExtraction, VulnerabilityFinding
from app.normalization.cwe_classifier import get_attack_type_for_cwe


ENDPOINT_RE = re.compile(r"(/(?:api/)?[A-Za-z0-9_./{}:-]+)")
PARAM_RE = re.compile(r"(?:parameter|param|field|input|query)\s+[`'\"]?([A-Za-z_][A-Za-z0-9_-]*)[`'\"]?", re.I)
VERSION_RE = re.compile(r"\b(?:version|v)\s*([0-9]+(?:\.[0-9]+){1,3})\b", re.I)
PACKAGE_RE = re.compile(r"(?:package|library|dependency)\s+[`'\"]?([A-Za-z0-9_.:@/-]+)[`'\"]?", re.I)
FILE_RE = re.compile(r"\b([A-Za-z0-9_./-]+\.(?:py|js|ts|java|go|rb|php|cs|jsx|tsx))\b")


def _first_match(pattern: re.Pattern[str], text: str) -> str | None:
    m = pattern.search(text)
    return m.group(1) if m else None


def extract_entities(finding: VulnerabilityFinding, canonical_cwe: str) -> EntityExtraction:
    text = " ".join([finding.title or "", finding.description or ""])
    endpoint = finding.endpoint or _first_match(ENDPOINT_RE, text)
    parameter = finding.parameter or _first_match(PARAM_RE, text)
    package = finding.package or _first_match(PACKAGE_RE, text)
    version = finding.version or _first_match(VERSION_RE, text)
    file_path = finding.file_path or _first_match(FILE_RE, text)
    attack_type = get_attack_type_for_cwe(canonical_cwe)

    return EntityExtraction(
        endpoint=endpoint,
        parameter=parameter,
        package=package,
        version=version,
        attack_type=attack_type,
        file_path=file_path,
    )
