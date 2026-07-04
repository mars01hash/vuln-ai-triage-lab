from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.schemas import TriageFeedback


class FeedbackStore:
    """Append-only human feedback log.

    Human approvals/rejections are critical training signals for future model
    evaluation, calibration, and drift monitoring.
    """

    def __init__(self, path: str | Path = "output/human_feedback.jsonl"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def add(self, feedback: TriageFeedback) -> dict[str, Any]:
        row = feedback.model_dump(mode="json")
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
        return {"saved": True, "path": str(self.path), "finding_id": feedback.finding_id}

    def summary(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"total_feedback": 0, "by_decision": {}, "by_finding": {}}
        by_decision: dict[str, int] = {}
        by_finding: dict[str, int] = {}
        total = 0
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            total += 1
            row = json.loads(line)
            decision = str(row.get("decision", "unknown"))
            finding_id = str(row.get("finding_id", "unknown"))
            by_decision[decision] = by_decision.get(decision, 0) + 1
            by_finding[finding_id] = by_finding.get(finding_id, 0) + 1
        return {"total_feedback": total, "by_decision": by_decision, "by_finding": by_finding}
