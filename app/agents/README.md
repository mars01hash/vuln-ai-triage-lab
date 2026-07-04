# Triage Agent Module

This component mimics local advisory LLM actions using deterministic logic to produce scheduling decisions and remediation fix text.

## Files
* `triage_agent.py`: Local triage agent logic.

## Python Usage
```python
from app.agents.triage_agent import local_triage_agent

decision, explanation, fix_advice = local_triage_agent(
    finding,
    canonical_cwe="CWE-89",
    cwe_name="SQL Injection",
    priority_score=0.85,
    risk_level="critical",
    reachable=True,
    duplicate_of=None,
    waf_rule_allowed=True
)

print(f"Action: {decision}")
print(f"Remediation Guide: {fix_advice}")
```

## Why it works
Using LLMs to make final blocking choices can introduce hallucination and latency. This module uses deterministic mapping for final queue scheduling, but wraps it in natural language summaries and CWE fix instructions for a developer-friendly experience.
