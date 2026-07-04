from __future__ import annotations

import hashlib
import math
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass


class EmbeddingProvider(ABC):
    """Common embedding interface.

    The project stays runnable with HashEmbeddingProvider, while production-like
    mode can use SentenceTransformerEmbeddingProvider after installing optional
    dependencies from requirements-advanced.txt.
    """

    name: str

    @abstractmethod
    def encode(self, text: str) -> list[float]:
        raise NotImplementedError


@dataclass
class HashEmbeddingProvider(EmbeddingProvider):
    """Deterministic local embedding provider.

    This is not semantically as strong as a neural embedding model, but it is
    fast, fully offline, reproducible, and useful for testing the vector-memory
    contract without downloading large models.
    """

    dimensions: int = 256
    name: str = "hash_embedding_v2"

    def encode(self, text: str) -> list[float]:
        tokens = re.findall(r"[a-zA-Z0-9_./:-]+", text.lower())
        vector = [0.0] * self.dimensions
        if not tokens:
            return vector

        for token in tokens:
            digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
            idx = int(digest[:8], 16) % self.dimensions
            sign = 1.0 if int(digest[8:10], 16) % 2 == 0 else -1.0
            vector[idx] += sign

        norm = math.sqrt(sum(v * v for v in vector)) or 1.0
        return [round(v / norm, 6) for v in vector]


class SentenceTransformerEmbeddingProvider(EmbeddingProvider):
    """Optional neural embedding provider.

    Install first:
      pip install -r requirements-advanced.txt

    Example model choices:
      - sentence-transformers/all-MiniLM-L6-v2
      - BAAI/bge-small-en-v1.5
    """

    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2"):
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "sentence-transformers is not installed. Install optional dependencies with: "
                "pip install -r requirements-advanced.txt"
            ) from exc

        self.model_name = model_name
        self.name = f"sentence_transformer:{model_name}"
        self.model = SentenceTransformer(model_name)

    def encode(self, text: str) -> list[float]:
        vector = self.model.encode([text], normalize_embeddings=True)[0]
        return [float(x) for x in vector]


def build_embedding_provider(provider: str = "hash", model_name: str | None = None) -> EmbeddingProvider:
    provider = provider.lower().strip()
    if provider in {"hash", "local", "offline"}:
        return HashEmbeddingProvider()
    if provider in {"sentence-transformer", "sentence_transformer", "sbert", "bge"}:
        return SentenceTransformerEmbeddingProvider(model_name or "sentence-transformers/all-MiniLM-L6-v2")
    raise ValueError(f"Unsupported embedding provider: {provider}")
