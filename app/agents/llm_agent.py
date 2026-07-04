from __future__ import annotations

import json
import os
from typing import Any

from app.agents.triage_agent import local_triage_agent
from app.normalization.cwe_classifier import get_fix_for_cwe
from app.schemas import VulnerabilityFinding


SYSTEM_PROMPT = """You are an application security triage assistant.
Return only valid JSON. Do not invent facts that are not present in the input.
Never approve deployment. Human approval must remain required for WAF or remediation actions.
"""


def _build_payload(
    finding: VulnerabilityFinding,
    canonical_cwe: str,
    cwe_name: str,
    priority_score: float,
    risk_level: str,
    reachable: bool,
    duplicate_of: str | None,
    waf_rule_allowed: bool,
) -> dict[str, Any]:
    return {
        "finding": finding.model_dump(mode="json"),
        "canonical_cwe": canonical_cwe,
        "cwe_name": cwe_name,
        "priority_score": priority_score,
        "risk_level": risk_level,
        "reachable": reachable,
        "duplicate_of": duplicate_of,
        "waf_rule_allowed": waf_rule_allowed,
        "constraints": [
            "Do not claim WAF deployment is approved.",
            "Human approval is mandatory for WAF proposals and remediation PRs.",
            "If evidence is SAST-only, mention uncertainty and false-positive risk.",
            "Keep recommendation specific but concise.",
        ],
        "required_json_schema": {
            "triage_decision": "string",
            "reasoning_summary": "string",
            "recommended_fix": "string",
        },
    }


def _call_openai_json(model: str, payload: dict[str, Any]) -> dict[str, str]:
    """Call OpenAI if available.

    This is optional. The project remains runnable without the OpenAI package or
    API key because run_llm_or_local_triage falls back to local deterministic triage.
    """
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise RuntimeError("openai package is not installed") from exc

    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY is not set")

    client = OpenAI()
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
        ],
        temperature=0.0,
        response_format={"type": "json_object"},
    )
    content = response.choices[0].message.content or "{}"
    parsed = json.loads(content)
    return {
        "triage_decision": str(parsed.get("triage_decision") or "manual_review_required"),
        "reasoning_summary": str(parsed.get("reasoning_summary") or "LLM returned no reasoning summary."),
        "recommended_fix": str(parsed.get("recommended_fix") or get_fix_for_cwe(str(payload["canonical_cwe"]))),
    }


def run_llm_or_local_triage(
    finding: VulnerabilityFinding,
    canonical_cwe: str,
    cwe_name: str,
    priority_score: float,
    risk_level: str,
    reachable: bool,
    duplicate_of: str | None,
    waf_rule_allowed: bool,
    use_llm: bool = False,
    model: str = "gpt-4o-mini",
) -> tuple[str, str, str, str]:
    """Return decision, reasoning, fix, and agent mode.

    The LLM is intentionally only used for explanation/recommendation text.
    Classification, scoring, WAF gating, and human approval stay in deterministic code.
    """
    if use_llm:
        payload = _build_payload(
            finding=finding,
            canonical_cwe=canonical_cwe,
            cwe_name=cwe_name,
            priority_score=priority_score,
            risk_level=risk_level,
            reachable=reachable,
            duplicate_of=duplicate_of,
            waf_rule_allowed=waf_rule_allowed,
        )
        try:
            parsed = _call_openai_json(model, payload)
            return (
                parsed["triage_decision"],
                parsed["reasoning_summary"],
                parsed["recommended_fix"],
                f"openai:{model}",
            )
        except Exception as exc:  # noqa: BLE001 - fallback is intentional for local demo stability
            decision, reasoning, fix = local_triage_agent(
                finding=finding,
                canonical_cwe=canonical_cwe,
                cwe_name=cwe_name,
                priority_score=priority_score,
                risk_level=risk_level,
                reachable=reachable,
                duplicate_of=duplicate_of,
                waf_rule_allowed=waf_rule_allowed,
            )
            reasoning = f"{reasoning} LLM fallback used because: {exc}"
            return decision, reasoning, fix, "local_fallback_after_llm_error"

    decision, reasoning, fix = local_triage_agent(
        finding=finding,
        canonical_cwe=canonical_cwe,
        cwe_name=cwe_name,
        priority_score=priority_score,
        risk_level=risk_level,
        reachable=reachable,
        duplicate_of=duplicate_of,
        waf_rule_allowed=waf_rule_allowed,
    )
    return decision, reasoning, fix, "local_rules"
