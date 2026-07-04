from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path

from app.schemas import NormalizedFinding


def write_markdown_report(results: list[NormalizedFinding], output_path: str | Path) -> None:
    """Write an interview-friendly batch triage report."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    risk_counts = Counter(item.risk_level for item in results)
    cwe_counts = Counter(item.canonical_cwe for item in results)
    source_counts = Counter(item.source_type.value for item in results)
    waf_allowed = sum(1 for item in results if item.waf_rule_allowed)
    duplicates = sum(1 for item in results if item.duplicate_of)

    by_asset: dict[str, list[NormalizedFinding]] = defaultdict(list)
    for item in results:
        by_asset[item.asset].append(item)

    lines: list[str] = []
    lines.append("# Vulnerability AI Triage Batch Report")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- Total findings processed: **{len(results)}**")
    lines.append(f"- Duplicate/similar findings detected: **{duplicates}**")
    lines.append(f"- WAF rule proposals allowed: **{waf_allowed}**")
    lines.append(f"- WAF proposals blocked/suppressed: **{len(results) - waf_allowed}**")
    lines.append("")

    lines.append("## Risk Distribution")
    lines.append("")
    lines.append("| Risk Level | Count |")
    lines.append("|---|---:|")
    for risk, count in risk_counts.most_common():
        lines.append(f"| {risk} | {count} |")
    lines.append("")

    lines.append("## CWE Distribution")
    lines.append("")
    lines.append("| CWE | Count |")
    lines.append("|---|---:|")
    for cwe, count in cwe_counts.most_common():
        lines.append(f"| {cwe} | {count} |")
    lines.append("")

    lines.append("## Source Distribution")
    lines.append("")
    lines.append("| Source | Count |")
    lines.append("|---|---:|")
    for source, count in source_counts.most_common():
        lines.append(f"| {source} | {count} |")
    lines.append("")

    lines.append("## Highest Priority Findings")
    lines.append("")
    lines.append("| Finding | Asset | CWE | Risk | Score | Reachable | WAF Allowed |")
    lines.append("|---|---|---|---|---:|---|---|")
    for item in sorted(results, key=lambda r: r.priority_score, reverse=True)[:10]:
        lines.append(
            f"| {item.finding_id} | {item.asset} | {item.canonical_cwe} | {item.risk_level} "
            f"| {item.priority_score:.3f} | {item.reachable} | {item.waf_rule_allowed} |"
        )
    lines.append("")

    lines.append("## Findings by Asset")
    lines.append("")
    for asset, items in sorted(by_asset.items()):
        lines.append(f"### {asset}")
        lines.append("")
        for item in sorted(items, key=lambda r: r.priority_score, reverse=True):
            lines.append(f"- **{item.finding_id}** — {item.canonical_cwe} / {item.risk_level} / score `{item.priority_score:.3f}`")
            lines.append(f"  - Decision: {item.triage_decision}")
            lines.append(f"  - Reason: {item.reasoning_summary}")
            if item.safety_notes:
                lines.append(f"  - Safety: {'; '.join(item.safety_notes)}")
        lines.append("")

    lines.append("## Notes for Interview Discussion")
    lines.append("")
    lines.append("- WAF rule eligibility is enforced by deterministic code, not by an LLM prompt.")
    lines.append("- Priority scoring combines CVSS, classifier confidence, reachability, exploit availability, business criticality, and asset exposure.")
    lines.append("- Duplicate detection uses lightweight local embeddings in the MVP; production upgrade can use Qdrant, Chroma, FAISS, or pgvector.")
    lines.append("- The ML classifier is intentionally simple and replaceable; production should train on historical labeled findings and evaluate calibration.")

    output_path.write_text("\n".join(lines), encoding="utf-8")
