from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.schemas import VulnerabilityFinding

DEFAULT_CALLGRAPH_PATH = Path("data/callgraph_routes.json")


def load_callgraph(path: str | Path = DEFAULT_CALLGRAPH_PATH) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {"routes": [], "unreachable_files": []}
    return json.loads(p.read_text(encoding="utf-8"))


def evaluate_callgraph_reachability(
    finding: VulnerabilityFinding,
    callgraph_path: str | Path = DEFAULT_CALLGRAPH_PATH,
) -> tuple[bool | None, str | None]:
    """Check a small route/callgraph fixture for reachability evidence.

    This simulates the integration contract for CodeQL/Joern/callgraph output
    without requiring heavyweight static-analysis tools in the default install.
    """
    graph = load_callgraph(callgraph_path)
    file_path = (finding.file_path or "").replace("\\", "/")
    endpoint = finding.endpoint or ""

    for blocked in graph.get("unreachable_files", []):
        if blocked and blocked in file_path:
            return False, f"Callgraph fixture marks file pattern '{blocked}' as unreachable/dead code"

    for route in graph.get("routes", []):
        route_endpoint = route.get("endpoint")
        file_hint = route.get("file_path_contains")
        if route_endpoint and endpoint == route_endpoint:
            return bool(route.get("reachable", False)), f"Callgraph route map matched endpoint {endpoint}"
        if file_hint and file_hint in file_path and endpoint and endpoint.startswith(str(route_endpoint or "")):
            return bool(route.get("reachable", False)), f"Callgraph route map matched file {file_path} and endpoint {endpoint}"

    return None, None
