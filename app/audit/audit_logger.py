from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from app.schemas import NormalizedFinding


def write_audit_log(results: Iterable[NormalizedFinding], output_path: str | Path) -> dict[str, object]:
    """Write append-only JSONL audit records for model/rule decisions."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("a", encoding="utf-8") as f:
        for result in results:
            count += 1
            record = {
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "finding_id": result.finding_id,
                "source_type": result.source_type.value,
                "canonical_cwe": result.canonical_cwe,
                "cwe_confidence": result.cwe_confidence,
                "priority_score": result.priority_score,
                "risk_level": result.risk_level,
                "reachable": result.reachable,
                "reachability_reason": result.reachability_reason,
                "waf_rule_allowed": result.waf_rule_allowed,
                "human_approval_required": result.human_approval_required,
                "approval_required_actions": result.approval_required_actions,
                "agent_mode": result.agent_mode,
                "memory_backend": result.memory_backend,
                "scoring_factors": result.scoring_factors,
                "safety_notes": result.safety_notes,
            }
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return {"audit_log": str(path), "records_appended": count}
