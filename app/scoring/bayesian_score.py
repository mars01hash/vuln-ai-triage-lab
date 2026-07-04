from __future__ import annotations

from app.schemas import AssetExposure, BusinessCriticality, SourceType, VulnerabilityFinding


BUSINESS_WEIGHT = {
    BusinessCriticality.low: 0.45,
    BusinessCriticality.medium: 0.65,
    BusinessCriticality.high: 0.85,
    BusinessCriticality.critical: 1.0,
}

EXPOSURE_WEIGHT = {
    AssetExposure.internal: 0.55,
    AssetExposure.partner: 0.75,
    AssetExposure.internet: 1.0,
}

SOURCE_CONFIDENCE = {
    SourceType.SAST: 0.68,
    SourceType.DAST: 0.86,
    SourceType.SCA: 0.72,
    SourceType.MANUAL: 0.75,
}


def calculate_priority_score(
    finding: VulnerabilityFinding,
    cwe_confidence: float,
    reachable: bool,
    duplicate_of: str | None,
) -> tuple[float, str, dict[str, float]]:
    """Confidence-weighted priority score.

    It is not a full Bayesian network, but it behaves like a transparent
    probability-inspired scoring layer. Each signal acts as evidence that shifts
    the final score.
    """
    cvss_weight = max(0.0, min(finding.cvss / 10.0, 1.0))
    source_weight = SOURCE_CONFIDENCE.get(finding.source_type, 0.7)
    reachability_weight = 1.0 if reachable else 0.42
    exploit_weight = 1.0 if finding.exploit_available else 0.65
    business_weight = BUSINESS_WEIGHT.get(finding.business_criticality, 0.65)
    exposure_weight = EXPOSURE_WEIGHT.get(finding.asset_exposure, 0.55)
    correlation_weight = 1.0 if (finding.dast_confirmed or finding.source_type == SourceType.DAST) else 0.75
    duplicate_weight = 0.88 if duplicate_of else 1.0

    score = (
        0.22 * cvss_weight
        + 0.18 * cwe_confidence
        + 0.15 * source_weight
        + 0.15 * reachability_weight
        + 0.10 * exploit_weight
        + 0.10 * business_weight
        + 0.07 * exposure_weight
        + 0.03 * correlation_weight
    ) * duplicate_weight

    score = round(max(0.0, min(score, 1.0)), 3)

    if score >= 0.82:
        risk = "critical"
    elif score >= 0.68:
        risk = "high"
    elif score >= 0.45:
        risk = "medium"
    else:
        risk = "low"

    factors = {
        "cvss_weight": round(cvss_weight, 3),
        "cwe_confidence": round(cwe_confidence, 3),
        "source_weight": round(source_weight, 3),
        "reachability_weight": round(reachability_weight, 3),
        "exploit_weight": round(exploit_weight, 3),
        "business_weight": round(business_weight, 3),
        "exposure_weight": round(exposure_weight, 3),
        "correlation_weight": round(correlation_weight, 3),
        "duplicate_weight": round(duplicate_weight, 3),
    }
    return score, risk, factors
