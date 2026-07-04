from __future__ import annotations

from pathlib import Path
from typing import Optional

from app.embeddings.providers import EmbeddingProvider, build_embedding_provider
from app.retrieval.hash_embeddings import cosine_similarity
from app.schemas import VulnerabilityFinding


class ChromaVulnerabilityMemory:
    """Optional Chroma-backed vulnerability memory.

    This class is intentionally optional so the project remains runnable without
    heavy packages. Install `chromadb` from requirements-advanced.txt to use it.
    """

    def __init__(
        self,
        persist_dir: str | Path = "output/chroma_memory",
        collection_name: str = "vulnerability_memory",
        similarity_threshold: float = 0.82,
        embedding_provider: EmbeddingProvider | None = None,
    ):
        try:
            import chromadb
        except ImportError as exc:
            raise ImportError(
                "chromadb is not installed. Install optional dependencies with: "
                "pip install -r requirements-advanced.txt"
            ) from exc

        self.persist_dir = Path(persist_dir)
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        self.similarity_threshold = similarity_threshold
        self.embedder = embedding_provider or build_embedding_provider("hash")
        self.client = chromadb.PersistentClient(path=str(self.persist_dir))
        self.collection = self.client.get_or_create_collection(collection_name)

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
        count = self.collection.count()
        return f"VULN-GROUP-{count + 1:04d}"

    def find_or_add(self, finding: VulnerabilityFinding, canonical_cwe: str) -> tuple[str, Optional[str], Optional[float]]:
        text = self._text_for_embedding(finding, canonical_cwe)
        embedding = self.embedder.encode(text)
        result = self.collection.query(query_embeddings=[embedding], n_results=5, include=["metadatas", "distances"])

        duplicate_of = None
        group_id = self._next_group_id()
        similarity = None

        ids = result.get("ids", [[]])[0]
        metadatas = result.get("metadatas", [[]])[0]
        distances = result.get("distances", [[]])[0]
        for candidate_id, metadata, distance in zip(ids, metadatas, distances):
            # Chroma cosine distance is typically 0 for identical. Convert to approximate similarity.
            score = max(0.0, min(1.0, 1.0 - float(distance)))
            if metadata.get("canonical_cwe") == canonical_cwe:
                score = min(1.0, score + 0.05)
            if metadata.get("asset") == finding.asset:
                score = min(1.0, score + 0.03)
            if finding.endpoint and metadata.get("endpoint") == finding.endpoint:
                score = min(1.0, score + 0.05)
            if score >= self.similarity_threshold:
                duplicate_of = str(candidate_id)
                group_id = str(metadata.get("group_id") or group_id)
                similarity = round(score, 3)
                break

        self.collection.add(
            ids=[finding.finding_id],
            embeddings=[embedding],
            documents=[text],
            metadatas=[{
                "group_id": group_id,
                "canonical_cwe": canonical_cwe,
                "asset": finding.asset,
                "endpoint": finding.endpoint or "",
                "embedding_provider": self.embedder.name,
            }],
        )
        return group_id, duplicate_of, similarity

    def summary(self) -> dict[str, int | str]:
        return {
            "backend": "chroma_vector_memory",
            "embedding_provider": self.embedder.name,
            "total_records": int(self.collection.count()),
            "unique_groups": -1,
            "unique_cwes": -1,
            "unique_assets": -1,
        }
