from __future__ import annotations

from dataclasses import dataclass
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
    """In-memory vector-like vulnerability memory for MVP.

    Replace with Chroma/Qdrant/FAISS/pgvector in a production-like version.
    """

    def __init__(self, similarity_threshold: float = 0.82):
        self.records: list[MemoryRecord] = []
        self.embedder = HashEmbedding()
        self.similarity_threshold = similarity_threshold

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
            # Strongly prefer same CWE and same asset, but allow close text matches.
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

        return group_id, duplicate_of, similarity
