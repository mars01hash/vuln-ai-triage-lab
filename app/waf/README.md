# WAF Gate Module

This component draft-proposes ModSecurity virtual patching rules for input validation vulnerabilities under strict code-enforced safety policies.

## Files
* `waf_gate.py`: ModSecurity rules generator and policy gate.

## Python Usage
```python
from app.waf.waf_gate import build_waf_rule_proposal

# Block rules are generated if:
# 1. Not a SAST-only finding (requires DAST confirmation or dynamic source)
# 2. Reached score threshold >= 0.75
# 3. Confirmed reachable
waf_rule_allowed, proposed_rule, notes = build_waf_rule_proposal(
    finding,
    canonical_cwe="CWE-89",
    priority_score=0.85,
    reachable=True
)

if waf_rule_allowed:
    print(f"Proposed Rule: {proposed_rule}")
else:
    print(f"Safety Gate block: {notes[0]}")
```

## Why it works
Automated blocking based on static analysis findings causes outages due to false-positive blocks on real users. By enforcing code-level gates that block WAF generation for SAST-only inputs and requiring explicit human approval, this gate safely creates virtual patches.
