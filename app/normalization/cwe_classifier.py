from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from app.schemas import VulnerabilityFinding


@dataclass(frozen=True)
class CWERule:
    cwe: str
    name: str
    keywords: tuple[str, ...]
    fix: str
    attack_type: str


CWE_RULES: list[CWERule] = [
    CWERule(
        "CWE-89",
        "SQL Injection",
        ("sql injection", "raw sql", "sql query", "select *", "union select", "unsanitized input", "parameterized", "database query"),
        "Use parameterized queries/prepared statements, validate input, and avoid string concatenation in SQL.",
        "SQL Injection",
    ),
    CWERule(
        "CWE-79",
        "Cross-Site Scripting",
        ("xss", "cross-site scripting", "script execution", "reflected script", "stored script", "html injection", "javascript", "innerhtml"),
        "Encode output by context, sanitize untrusted HTML, and use safe templating APIs.",
        "Cross-Site Scripting",
    ),
    CWERule(
        "CWE-22",
        "Path Traversal",
        ("path traversal", "../", "directory traversal", "file path", "arbitrary file", "read file", "dot dot slash"),
        "Normalize and constrain file paths, use allowlists, and block traversal sequences.",
        "Path Traversal",
    ),
    CWERule(
        "CWE-287",
        "Improper Authentication",
        ("authentication bypass", "improper authentication", "missing authentication", "unauthenticated", "login bypass"),
        "Require authentication on protected routes and verify identity server-side for every sensitive action.",
        "Authentication Weakness",
    ),
    CWERule(
        "CWE-862",
        "Missing Authorization",
        ("missing authorization", "broken access control", "idor", "insecure direct object reference", "access control", "privilege"),
        "Enforce object-level authorization checks and deny access by default.",
        "Broken Access Control",
    ),
    CWERule(
        "CWE-798",
        "Use of Hard-coded Credentials",
        ("hardcoded credential", "hard-coded credential", "password in source", "api key", "secret key", "private key", "token in code"),
        "Remove secrets from source code, rotate exposed credentials, and use a secret manager.",
        "Hard-coded Secret",
    ),
    CWERule(
        "CWE-502",
        "Deserialization of Untrusted Data",
        ("deserialization", "pickle", "untrusted object", "unsafe deserialize", "java serialization", "yaml.load"),
        "Avoid unsafe deserialization of untrusted input and use safe serializers or strict allowlists.",
        "Unsafe Deserialization",
    ),
    CWERule(
        "CWE-200",
        "Exposure of Sensitive Information",
        ("sensitive information", "information exposure", "leak", "pii", "stack trace", "debug info", "secret exposed"),
        "Remove sensitive data from responses/logs, apply access control, and mask sensitive fields.",
        "Sensitive Data Exposure",
    ),
    CWERule(
        "CWE-918",
        "Server-Side Request Forgery",
        ("ssrf", "server-side request forgery", "internal url", "metadata service", "169.254.169.254", "fetch url"),
        "Use URL allowlists, block internal IP ranges, and isolate outbound network access.",
        "SSRF",
    ),
    CWERule(
        "CWE-352",
        "Cross-Site Request Forgery",
        ("csrf", "cross-site request forgery", "missing csrf", "anti-csrf"),
        "Use CSRF tokens, SameSite cookies, and verify state-changing requests server-side.",
        "CSRF",
    ),
    CWERule(
        "CWE-400",
        "Uncontrolled Resource Consumption",
        ("denial of service", "resource exhaustion", "unbounded", "rate limit", "large payload", "memory exhaustion"),
        "Apply rate limits, size limits, timeouts, pagination, and resource quotas.",
        "Denial of Service",
    ),
]

DEFAULT_CWE = CWERule(
    "CWE-20",
    "Improper Input Validation",
    ("input", "validation"),
    "Validate, normalize, and constrain all untrusted input at trust boundaries.",
    "Input Validation",
)

CWE_BY_ID = {rule.cwe: rule for rule in CWE_RULES}
CWE_BY_ID[DEFAULT_CWE.cwe] = DEFAULT_CWE


def _normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()


def classify_cwe(finding: VulnerabilityFinding) -> tuple[str, str, float, list[str]]:
    """Return canonical CWE, name, confidence, and evidence.

    This is a deterministic local classifier for MVP use. Replace it later with
    TF-IDF/LogReg, Transformer, CodeBERT, or a hybrid classifier.
    """
    if finding.cwe and finding.cwe in CWE_BY_ID:
        rule = CWE_BY_ID[finding.cwe]
        return rule.cwe, rule.name, 0.95, ["CWE supplied by source and recognized"]

    text = _normalize_text(" ".join([
        finding.title or "",
        finding.description or "",
        finding.endpoint or "",
        finding.parameter or "",
        finding.file_path or "",
        finding.package or "",
    ]))

    best_rule: Optional[CWERule] = None
    best_hits: list[str] = []

    for rule in CWE_RULES:
        hits = [kw for kw in rule.keywords if kw in text]
        if len(hits) > len(best_hits):
            best_rule = rule
            best_hits = hits

    if not best_rule:
        best_rule = DEFAULT_CWE
        best_hits = ["generic input/security weakness"]
        return best_rule.cwe, best_rule.name, 0.45, best_hits

    # Simple confidence: base + keyword evidence density.
    confidence = min(0.98, 0.55 + 0.12 * len(best_hits))

    # Strong phrases get a small boost.
    strong_phrases = {"sql injection", "xss", "ssrf", "csrf", "path traversal", "deserialization", "hardcoded credential"}
    if any(hit in strong_phrases for hit in best_hits):
        confidence = min(0.98, confidence + 0.15)

    return best_rule.cwe, best_rule.name, round(confidence, 3), best_hits


def get_fix_for_cwe(cwe: str) -> str:
    return CWE_BY_ID.get(cwe, DEFAULT_CWE).fix


def get_attack_type_for_cwe(cwe: str) -> str:
    return CWE_BY_ID.get(cwe, DEFAULT_CWE).attack_type
