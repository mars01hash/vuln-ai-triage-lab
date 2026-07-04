# Policy Module

This component isolates critical approval policies into deterministic rules.

## Files
* `approval_policy.py`: Policy evaluation logic.

## Python Usage
```python
from app.policy.approval_policy import required_approval_actions

# Returns list of required reviews (e.g. "review_waf_virtual_patch")
reviews = required_approval_actions(result)
print(f"Required approvals: {reviews}")
```

## Why it works
Automated recommendations should not bypass critical business controls. By isolating approval policies (such as requiring human checks on WAF patches, critical vulnerabilities, or duplicate merges) in code instead of prompting an LLM, the system guarantees safety compliance.
