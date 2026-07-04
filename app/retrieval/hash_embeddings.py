from __future__ import annotations

import hashlib
import math
import re
from collections import Counter

TOKEN_RE = re.compile(r"[a-zA-Z0-9_./:-]+")


class HashEmbedding:
    """Tiny local embedding model.

    This is not a real semantic embedding model. It creates a normalized hashed
    bag-of-words vector so the project can run without external models.

    Upgrade path:
    - sentence-transformers/all-MiniLM-L6-v2
    - BAAI/bge-small-en-v1.5
    - OpenAI embeddings
    """

    def __init__(self, dimensions: int = 128):
        self.dimensions = dimensions

    def encode(self, text: str) -> list[float]:
        tokens = TOKEN_RE.findall(text.lower())
        counts = Counter(tokens)
        vec = [0.0] * self.dimensions

        for token, count in counts.items():
            digest = hashlib.md5(token.encode("utf-8")).hexdigest()
            idx = int(digest, 16) % self.dimensions
            vec[idx] += 1.0 + math.log(count)

        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]


def cosine_similarity(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    return sum(x * y for x, y in zip(a, b))
