from __future__ import annotations

from app.schemas import NormalizedFinding


def required_approval_actions(result: NormalizedFinding) -> list[str]:
    """List actions that require human approval.

    This keeps approval policy as deterministic code rather than a prompt-level
    instruction. The agent may recommend, but policy decides what needs approval.
    """
    actions: list[str] = []
    if result.waf_rule_allowed and result.proposed_waf_rule:
        actions.append("review_waf_virtual_patch")
    if result.risk_level in {"critical", "high"}:
        actions.append("review_remediation_plan")
    if result.duplicate_of:
        actions.append("review_duplicate_grouping")
    return actions
