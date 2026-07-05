from __future__ import annotations

from app.schemas import VulnerabilityFinding
from app.reachability.callgraph_reachability import evaluate_callgraph_reachability


PUBLIC_ENDPOINT_HINTS = ("/api/", "/login", "/search", "/checkout", "/orders", "/upload", "/admin")


def evaluate_reachability(finding: VulnerabilityFinding) -> tuple[bool, str]:
    """MVP reachability gate.

    In real systems, replace with CodeQL, Joern, callgraph/data-flow analysis,
    framework route mapping, and runtime telemetry.
    """
    if finding.reachable is not None:
        return finding.reachable, "Reachability supplied by input signal"

    callgraph_reachable, callgraph_reason = evaluate_callgraph_reachability(finding)
    if callgraph_reachable is not None:
        return callgraph_reachable, callgraph_reason or "Callgraph reachability signal available"

    if finding.source_type == "DAST":
        return True, "DAST finding implies endpoint was dynamically reachable"

    if finding.endpoint and any(hint in finding.endpoint for hint in PUBLIC_ENDPOINT_HINTS):
        return True, "Endpoint pattern looks externally or application reachable"

    if finding.source_type == "SCA":
        return False, "SCA package finding requires dependency reachability confirmation"

    return False, "No reachability evidence available"
