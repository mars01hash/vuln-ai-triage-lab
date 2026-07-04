from __future__ import annotations

from app.normalization.cwe_classifier import get_fix_for_cwe
from app.schemas import VulnerabilityFinding


def local_triage_agent(
    finding: VulnerabilityFinding,
    canonical_cwe: str,
    cwe_name: str,
    priority_score: float,
    risk_level: str,
    reachable: bool,
    duplicate_of: str | None,
    waf_rule_allowed: bool,
) -> tuple[str, str, str]:
    """Local deterministic agent-like output.

    Upgrade path: replace with LangGraph + LLM structured outputs. Keep hard
    safety gates outside the LLM.
    """
    if duplicate_of:
        decision = "review_duplicate_group"
    elif risk_level in {"critical", "high"} and reachable:
        decision = "urgent_fix_required"
    elif not reachable:
        decision = "deprioritize_until_reachability_confirmed"
    else:
        decision = "standard_security_backlog"

    reason_parts = [
        f"Mapped to {canonical_cwe} ({cwe_name}).",
        f"Priority score is {priority_score:.2f}, categorized as {risk_level}.",
    ]

    if reachable:
        reason_parts.append("Reachability evidence indicates the vulnerable path is reachable.")
    else:
        reason_parts.append("Reachability is not confirmed, so exploitation likelihood is reduced.")

    if duplicate_of:
        reason_parts.append(f"This appears similar to existing finding {duplicate_of}, so deduplication review is recommended.")

    if waf_rule_allowed:
        reason_parts.append("A WAF virtual patch proposal can be reviewed by a human approver.")
    else:
        reason_parts.append("WAF proposal is blocked or not eligible under safety constraints.")

    fix = get_fix_for_cwe(canonical_cwe)
    return decision, " ".join(reason_parts), fix
