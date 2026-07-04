from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Generic, TypeVar

T = TypeVar("T")


@dataclass
class WorkflowNode(Generic[T]):
    name: str
    fn: Callable[[T], T]


@dataclass
class SimpleWorkflowGraph(Generic[T]):
    """Tiny local workflow graph used to explain the agentic architecture.

    It avoids a hard LangGraph dependency in the default install. In production,
    each node can be migrated to LangGraph while preserving the same node order.
    """

    nodes: list[WorkflowNode[T]] = field(default_factory=list)

    def add_node(self, name: str, fn: Callable[[T], T]) -> "SimpleWorkflowGraph[T]":
        self.nodes.append(WorkflowNode(name=name, fn=fn))
        return self

    def run(self, state: T) -> T:
        for node in self.nodes:
            state = node.fn(state)
        return state

    def describe(self) -> list[str]:
        return [node.name for node in self.nodes]


TRIAGE_WORKFLOW_STEPS = [
    "ingest_canonical_finding",
    "normalize_cwe",
    "extract_entities",
    "retrieve_similar_findings",
    "evaluate_reachability",
    "score_priority",
    "enforce_waf_policy",
    "generate_triage_explanation",
    "require_human_approval_for_risky_actions",
]
