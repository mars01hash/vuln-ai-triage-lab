from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from app.retrieval.hash_embeddings import HashEmbedding, cosine_similarity
from app.schemas import VulnerabilityFinding


@dataclass
class MemoryRecord:
    finding_id: str
    group_id: str
    canonical_cwe: str
    asset: str
    endpoint: str | None
    text: str
    embedding: list[float]


class VulnerabilityMemory:
    """Vector-like vulnerability memory for MVP.

    It starts in-memory, but can be backed by a JSON file using memory_path.
    Replace with Chroma/Qdrant/FAISS/pgvector in a production-like version.
    """

    def __init__(self, similarity_threshold: float = 0.82, memory_path: str | Path | None = None):
        self.records: list[MemoryRecord] = []
        self.embedder = HashEmbedding()
        self.similarity_threshold = similarity_threshold
        self.memory_path = Path(memory_path) if memory_path else None
        if self.memory_path and self.memory_path.exists():
            self.load()

    def load(self) -> None:
        if not self.memory_path or not self.memory_path.exists():
            return
        payload = json.loads(self.memory_path.read_text(encoding="utf-8"))
        self.records = [MemoryRecord(**row) for row in payload.get("records", [])]

    def save(self) -> None:
        if not self.memory_path:
            return
        self.memory_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "similarity_threshold": self.similarity_threshold,
            "records": [asdict(record) for record in self.records],
        }
        self.memory_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _text_for_embedding(self, finding: VulnerabilityFinding, canonical_cwe: str) -> str:
        return " ".join([
            canonical_cwe,
            finding.asset or "",
            finding.endpoint or "",
            finding.parameter or "",
            finding.title or "",
            finding.description or "",
        ])

    def find_or_add(self, finding: VulnerabilityFinding, canonical_cwe: str) -> tuple[str, Optional[str], Optional[float]]:
        text = self._text_for_embedding(finding, canonical_cwe)
        embedding = self.embedder.encode(text)

        best: MemoryRecord | None = None
        best_score = 0.0
        for record in self.records:
            score = cosine_similarity(embedding, record.embedding)
            if canonical_cwe == record.canonical_cwe:
                score += 0.05
            if finding.asset == record.asset:
                score += 0.03
            if finding.endpoint and finding.endpoint == record.endpoint:
                score += 0.05
            score = min(score, 1.0)
            if score > best_score:
                best_score = score
                best = record

        if best and best_score >= self.similarity_threshold:
            group_id = best.group_id
            duplicate_of = best.finding_id
            similarity = round(best_score, 3)
        else:
            group_id = f"VULN-GROUP-{len(self.records) + 1:04d}"
            duplicate_of = None
            similarity = None

        self.records.append(MemoryRecord(
            finding_id=finding.finding_id,
            group_id=group_id,
            canonical_cwe=canonical_cwe,
            asset=finding.asset,
            endpoint=finding.endpoint,
            text=text,
            embedding=embedding,
        ))
        self.save()
        return group_id, duplicate_of, similarity

    def summary(self) -> dict[str, int]:
        by_cwe: dict[str, int] = {}
        by_asset: dict[str, int] = {}
        for record in self.records:
            by_cwe[record.canonical_cwe] = by_cwe.get(record.canonical_cwe, 0) + 1
            by_asset[record.asset] = by_asset.get(record.asset, 0) + 1
        return {
            "total_records": len(self.records),
            "unique_groups": len({record.group_id for record in self.records}),
            "unique_cwes": len(by_cwe),
            "unique_assets": len(by_asset),
        }
