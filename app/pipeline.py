from __future__ import annotations

from pathlib import Path

from app.agents.triage_agent import local_triage_agent
from app.ml.cwe_ml_classifier import MLCWEClassifier
from app.normalization.cwe_classifier import classify_cwe
from app.normalization.entity_extractor import extract_entities
from app.reachability.reachability_gate import evaluate_reachability
from app.scoring.bayesian_score import calculate_priority_score
from app.schemas import NormalizedFinding, VulnerabilityFinding
from app.storage.memory_store import VulnerabilityMemory
from app.waf.waf_gate import build_waf_rule_proposal


class TriagePipeline:
    def __init__(
        self,
        memory: VulnerabilityMemory | None = None,
        use_ml_classifier: bool = False,
        model_path: str | Path = "models/cwe_tfidf_logreg.joblib",
    ):
        self.memory = memory or VulnerabilityMemory()
        self.use_ml_classifier = use_ml_classifier
        self.ml_classifier: MLCWEClassifier | None = None
        if use_ml_classifier:
            self.ml_classifier = MLCWEClassifier.load(model_path)

    def _classify(self, finding: VulnerabilityFinding) -> tuple[str, str, float, list[str]]:
        if self.ml_classifier:
            prediction = self.ml_classifier.predict_finding(finding)
            return prediction.cwe, prediction.cwe_name, prediction.confidence, prediction.evidence
        return classify_cwe(finding)

    def process_one(self, finding: VulnerabilityFinding) -> NormalizedFinding:
        canonical_cwe, cwe_name, cwe_confidence, evidence = self._classify(finding)
        entities = extract_entities(finding, canonical_cwe)
        reachable, reachability_reason = evaluate_reachability(finding)
        duplicate_group_id, duplicate_of, similarity = self.memory.find_or_add(finding, canonical_cwe)

        priority_score, risk_level, scoring_factors = calculate_priority_score(
            finding=finding,
            cwe_confidence=cwe_confidence,
            reachable=reachable,
            duplicate_of=duplicate_of,
        )

        waf_rule_allowed, proposed_waf_rule, safety_notes = build_waf_rule_proposal(
            finding=finding,
            canonical_cwe=canonical_cwe,
            priority_score=priority_score,
            reachable=reachable,
        )

        triage_decision, reasoning_summary, recommended_fix = local_triage_agent(
            finding=finding,
            canonical_cwe=canonical_cwe,
            cwe_name=cwe_name,
            priority_score=priority_score,
            risk_level=risk_level,
            reachable=reachable,
            duplicate_of=duplicate_of,
            waf_rule_allowed=waf_rule_allowed,
        )

        return NormalizedFinding(
            finding_id=finding.finding_id,
            source_type=finding.source_type,
            tool_name=finding.tool_name,
            title=finding.title,
            description=finding.description,
            asset=finding.asset,
            canonical_cwe=canonical_cwe,
            cwe_name=cwe_name,
            cwe_confidence=cwe_confidence,
            evidence=evidence,
            entities=entities,
            reachable=reachable,
            reachability_reason=reachability_reason,
            duplicate_group_id=duplicate_group_id,
            duplicate_of=duplicate_of,
            similarity_to_duplicate=similarity,
            priority_score=priority_score,
            risk_level=risk_level,
            scoring_factors=scoring_factors,
            triage_decision=triage_decision,
            reasoning_summary=reasoning_summary,
            recommended_fix=recommended_fix,
            waf_rule_allowed=waf_rule_allowed,
            proposed_waf_rule=proposed_waf_rule,
            human_approval_required=True,
            safety_notes=safety_notes,
        )

    def process_many(self, findings: list[VulnerabilityFinding]) -> list[NormalizedFinding]:
        return [self.process_one(finding) for finding in findings]
