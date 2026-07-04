from __future__ import annotations

from app.schemas import SourceType, VulnerabilityFinding

WAF_ELIGIBLE_CWES = {"CWE-89", "CWE-79", "CWE-22", "CWE-918", "CWE-352"}


def build_waf_rule_proposal(finding: VulnerabilityFinding, canonical_cwe: str, priority_score: float, reachable: bool) -> tuple[bool, str | None, list[str]]:
    """Generate a WAF proposal only when hard safety conditions pass.

    Important: this does not deploy rules. It only creates a proposal requiring
    human approval.
    """
    notes: list[str] = []

    if finding.source_type == SourceType.SAST and not finding.dast_confirmed:
        notes.append("Blocked WAF proposal: SAST-only signals cannot trigger WAF rule generation.")
        return False, None, notes

    if canonical_cwe not in WAF_ELIGIBLE_CWES:
        notes.append(f"Blocked WAF proposal: {canonical_cwe} is not eligible for generic WAF virtual patching in this MVP.")
        return False, None, notes

    if not reachable:
        notes.append("Blocked WAF proposal: finding is not confirmed reachable.")
        return False, None, notes

    if priority_score < 0.75:
        notes.append("Blocked WAF proposal: priority score below WAF proposal threshold 0.75.")
        return False, None, notes

    endpoint = finding.endpoint or "REQUEST_URI"
    parameter = finding.parameter or "ARGS"

    if canonical_cwe == "CWE-89":
        rule = f'SecRule ARGS:{parameter} "(?i:(union\\s+select|select\\s+.*from|or\\s+1=1))" "id:100001,phase:2,deny,status:403,msg:\'Proposed SQLi virtual patch for {endpoint}\'"'
    elif canonical_cwe == "CWE-79":
        rule = f'SecRule ARGS:{parameter} "(?i:(<script|javascript:|onerror=|onload=))" "id:100002,phase:2,deny,status:403,msg:\'Proposed XSS virtual patch for {endpoint}\'"'
    elif canonical_cwe == "CWE-22":
        rule = f'SecRule ARGS:{parameter} "(?:\\.\\./|\\.\\.\\\\)" "id:100003,phase:2,deny,status:403,msg:\'Proposed path traversal virtual patch for {endpoint}\'"'
    elif canonical_cwe == "CWE-918":
        rule = f'SecRule ARGS:{parameter} "(?i:(169\\.254\\.169\\.254|localhost|127\\.0\\.0\\.1))" "id:100004,phase:2,deny,status:403,msg:\'Proposed SSRF virtual patch for {endpoint}\'"'
    else:
        rule = f'# Proposed WAF rule for {canonical_cwe} at {endpoint}. Requires security review before use.'

    notes.append("WAF rule is only a proposal and requires human approval before deployment.")
    return True, rule, notes
