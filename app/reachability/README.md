# Reachability Gate Module

This component evaluates if an attacker can reach a vulnerable code path using static metadata and dynamic scanner heuristics.

## Files
* `reachability_gate.py`: Reachability evaluation engine.

## Python Usage
```python
from app.reachability.reachability_gate import evaluate_reachability

# DAST findings are automatically marked reachable;
# SCA packages default to unreachable unless verified.
reachable, reason = evaluate_reachability(finding)
print(f"Reachable: {reachable} (Reason: {reason})")
```

## Why it works
Over half of static scan results lie in dead paths or internal tools that can't be reached by an attacker. By checking for public API endpoint suffixes and confirming dynamic DAST activity, this gate flags non-exploitable findings so they can be safely deprioritized.
