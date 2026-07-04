# LLM Safety Notes

## Key Rule

The LLM is not the authority for security-critical actions.

## LLM Can Do

- Summarize why a finding matters.
- Draft developer-friendly fix guidance.
- Explain evidence.
- Produce structured triage text.

## LLM Cannot Do

- Override WAF policy.
- Deploy a WAF rule.
- Approve remediation automatically.
- Change priority score.
- Suppress findings without deterministic policy support.

## Why

Application security workflows have asymmetric error costs. A false positive WAF rule can block legitimate users. A false negative vulnerability triage decision can allow exploitation. Therefore, system-level controls are safer than prompt-level instructions.
