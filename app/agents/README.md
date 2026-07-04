# Triage Agent Module

This component coordinates scheduling decisions and natural language remediation logs using either local deterministic rule models or optional OpenAI LLM agents.

## Files
* `triage_agent.py`: Local deterministic triage logic.
* `llm_agent.py`: Optional OpenAI JSON agent with automatic local rules fallback.
* `agent_graph.py`: Simple workflow graph wrapper to outline execution order.

## Python Usage
Using OpenAI agent with fallback:
```python
from app.agents.llm_agent import run_llm_or_local_triage

# Automatically runs OpenAI if use_llm=True and key is set;
# otherwise falls back to local triage.
decision, explanation, fix_advice, agent_mode = run_llm_or_local_triage(
    finding,
    canonical_cwe="CWE-89",
    cwe_name="SQL Injection",
    priority_score=0.85,
    risk_level="critical",
    reachable=True,
    duplicate_of=None,
    waf_rule_allowed=True,
    use_llm=True,
    model="gpt-4o-mini"
)

print(f"Agent: {agent_mode}, Decision: {decision}")
```

## Why it works
Placing critical security routing decisions inside generative models introduces security risks (hallucinations and prompt injections). The triage agent splits responsibilities: classification and risk scoring are enforced in code, while explanation text is delegated to LLMs with stable error fallbacks.
