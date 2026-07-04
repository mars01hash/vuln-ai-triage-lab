# Priority Scoring Module

This component calculates a context-aware risk priority score combining CVSS, reachability, business exposure, exploit availability, and correlation signals.

## Files
* `bayesian_score.py`: Risk prioritizer scoring equation.

## Python Usage
```python
from app.scoring.bayesian_score import calculate_priority_score

score, risk_level, factors = calculate_priority_score(
    finding=finding,
    cwe_confidence=0.95,
    reachable=True,
    duplicate_of=None
)

print(f"Risk: {risk_level} (Score: {score:.3f})")
print(f"CVSS Weight: {factors['cvss_weight']}, Exposure: {factors['exposure_weight']}")
```

## Why it works
CVSS scores represent static technical severity, not actual risk. This module combines business exposure (internet-facing vs. internal) and exploit availability into a transparent linear weighted formula, helping teams tackle what is actually dangerous first.
