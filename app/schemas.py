from __future__ import annotations

from enum import Enum
from typing import Any, Optional, Literal
from pydantic import BaseModel, Field


class SourceType(str, Enum):
    SAST = "SAST"
    DAST = "DAST"
    SCA = "SCA"
    MANUAL = "MANUAL"


class BusinessCriticality(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AssetExposure(str, Enum):
    internal = "internal"
    partner = "partner"
    internet = "internet"


class VulnerabilityFinding(BaseModel):
    finding_id: str
    source_type: SourceType
    tool_name: str = "unknown"
    title: str
    description: str

    cwe: Optional[str] = None
    cvss: float = Field(default=5.0, ge=0.0, le=10.0)

    asset: str = "unknown-asset"
    endpoint: Optional[str] = None
    parameter: Optional[str] = None
    file_path: Optional[str] = None
    package: Optional[str] = None
    version: Optional[str] = None

    reachable: Optional[bool] = None
    exploit_available: bool = False
    business_criticality: BusinessCriticality = BusinessCriticality.medium
    asset_exposure: AssetExposure = AssetExposure.internal
    dast_confirmed: bool = False

    raw: dict[str, Any] = Field(default_factory=dict)


class EntityExtraction(BaseModel):
    endpoint: Optional[str] = None
    parameter: Optional[str] = None
    package: Optional[str] = None
    version: Optional[str] = None
    attack_type: Optional[str] = None
    file_path: Optional[str] = None


class NormalizedFinding(BaseModel):
    finding_id: str
    source_type: SourceType
    tool_name: str
    title: str
    description: str
    asset: str

    canonical_cwe: str
    cwe_name: str
    cwe_confidence: float
    evidence: list[str] = Field(default_factory=list)
    entities: EntityExtraction

    reachable: bool
    reachability_reason: str

    duplicate_group_id: str
    duplicate_of: Optional[str] = None
    similarity_to_duplicate: Optional[float] = None

    priority_score: float
    risk_level: str
    scoring_factors: dict[str, float]

    triage_decision: str
    reasoning_summary: str
    recommended_fix: str

    waf_rule_allowed: bool
    proposed_waf_rule: Optional[str] = None
    human_approval_required: bool = True
    safety_notes: list[str] = Field(default_factory=list)

    agent_mode: str = "local_rules"
    memory_backend: str = "in_memory"
    approval_required_actions: list[str] = Field(default_factory=list)


class TriageFeedback(BaseModel):
    finding_id: str
    decision: Literal["approved", "rejected", "needs_changes", "false_positive", "true_positive"]
    reviewer: Optional[str] = None
    notes: Optional[str] = None
    corrected_cwe: Optional[str] = None
    corrected_priority: Optional[str] = None
    waf_rule_approved: Optional[bool] = None
    remediation_approved: Optional[bool] = None
