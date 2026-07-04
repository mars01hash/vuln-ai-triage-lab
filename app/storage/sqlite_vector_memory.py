from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Optional

from app.embeddings.providers import EmbeddingProvider, build_embedding_provider
from app.retrieval.hash_embeddings import cosine_similarity
from app.schemas import VulnerabilityFinding


class SqliteVulnerabilityMemory:
    """Persistent vector-like vulnerability memory backed by SQLite.

    It stores embeddings as JSON arrays so the project remains dependency-light.
    Production upgrade paths: pgvector, Qdrant, Chroma, FAISS, or a managed vector DB.
    """

    def __init__(
        self,
        db_path: str | Path = "output/vulnerability_memory.sqlite",
        similarity_threshold: float = 0.82,
        embedding_provider: EmbeddingProvider | None = None,
    ):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.similarity_threshold = similarity_threshold
        self.embedder = embedding_provider or build_embedding_provider("hash")
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS memory_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id TEXT NOT NULL,
                    group_id TEXT NOT NULL,
                    canonical_cwe TEXT NOT NULL,
                    asset TEXT NOT NULL,
                    endpoint TEXT,
                    text TEXT NOT NULL,
                    embedding_json TEXT NOT NULL,
                    embedding_provider TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_memory_cwe ON memory_records(canonical_cwe)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_memory_asset ON memory_records(asset)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_memory_group ON memory_records(group_id)")

    def _text_for_embedding(self, finding: VulnerabilityFinding, canonical_cwe: str) -> str:
        return " ".join([
            canonical_cwe,
            finding.asset or "",
            finding.endpoint or "",
            finding.parameter or "",
            finding.title or "",
            finding.description or "",
            finding.file_path or "",
            finding.package or "",
            finding.version or "",
        ]).strip()

    def _next_group_id(self) -> str:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(DISTINCT group_id) AS n FROM memory_records").fetchone()
            return f"VULN-GROUP-{int(row['n']) + 1:04d}"

    def find_or_add(self, finding: VulnerabilityFinding, canonical_cwe: str) -> tuple[str, Optional[str], Optional[float]]:
        text = self._text_for_embedding(finding, canonical_cwe)
        embedding = self.embedder.encode(text)

        best_row: sqlite3.Row | None = None
        best_score = 0.0

        with self._connect() as conn:
            rows = conn.execute(
                "SELECT finding_id, group_id, canonical_cwe, asset, endpoint, embedding_json FROM memory_records"
            ).fetchall()

            for row in rows:
                stored_embedding = json.loads(row["embedding_json"])
                score = cosine_similarity(embedding, stored_embedding)
                if canonical_cwe == row["canonical_cwe"]:
                    score += 0.05
                if finding.asset == row["asset"]:
                    score += 0.03
                if finding.endpoint and finding.endpoint == row["endpoint"]:
                    score += 0.05
                score = min(score, 1.0)
                if score > best_score:
                    best_score = score
                    best_row = row

            if best_row is not None and best_score >= self.similarity_threshold:
                group_id = str(best_row["group_id"])
                duplicate_of = str(best_row["finding_id"])
                similarity = round(best_score, 3)
            else:
                group_id = self._next_group_id()
                duplicate_of = None
                similarity = None

            conn.execute(
                """
                INSERT INTO memory_records
                    (finding_id, group_id, canonical_cwe, asset, endpoint, text, embedding_json, embedding_provider)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.finding_id,
                    group_id,
                    canonical_cwe,
                    finding.asset,
                    finding.endpoint,
                    text,
                    json.dumps(embedding),
                    self.embedder.name,
                ),
            )

        return group_id, duplicate_of, similarity

    def summary(self) -> dict[str, int | str]:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) AS n FROM memory_records").fetchone()["n"]
            groups = conn.execute("SELECT COUNT(DISTINCT group_id) AS n FROM memory_records").fetchone()["n"]
            cwes = conn.execute("SELECT COUNT(DISTINCT canonical_cwe) AS n FROM memory_records").fetchone()["n"]
            assets = conn.execute("SELECT COUNT(DISTINCT asset) AS n FROM memory_records").fetchone()["n"]
        return {
            "backend": "sqlite_vector_memory",
            "embedding_provider": self.embedder.name,
            "total_records": int(total),
            "unique_groups": int(groups),
            "unique_cwes": int(cwes),
            "unique_assets": int(assets),
        }
