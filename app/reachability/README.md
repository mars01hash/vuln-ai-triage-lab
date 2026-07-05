# Reachability Gate Module

This component evaluates if an attacker can reach a vulnerable code path using static metadata, callgraph routing tables, and dynamic scanner heuristics.

## Files
* `reachability_gate.py`: Reachability evaluation engine.
* `callgraph_reachability.py`: Callgraph matching helper.

## Python Usage
```python
from app.reachability.reachability_gate import evaluate_reachability

# Evaluates callgraph route maps and public endpoint suffixes
reachable, reason = evaluate_reachability(finding)
print(f"Reachable: {reachable} (Reason: {reason})")
```

## Why it works
Over half of static scan results lie in dead paths or internal components that can't be reached by an attacker. By checking for public API endpoint suffixes, comparing callgraph route map traces, and confirming dynamic DAST activity, this gate flags non-exploitable findings so they can be safely deprioritized.

