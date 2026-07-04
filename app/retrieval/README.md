# Retrieval & Similarity Module

This component tokenizes and hashes text descriptions into vectors to calculate cosine similarity without relying on deep learning models.

## Files
* `hash_embeddings.py`: Hash-based bag-of-words vector encoder and cosine similarity calculator.

## Python Usage
```python
from app.retrieval.hash_embeddings import HashEmbedding, cosine_similarity

embedder = HashEmbedding(dimensions=128)

vec_a = embedder.encode("Potential SQL injection in parameter order_id")
vec_b = embedder.encode("Raw SQL queries detected in order_id field")

similarity = cosine_similarity(vec_a, vec_b)
print(f"Similarity: {similarity:.3f}")
```

## Why it works
Semantic vector embeddings (e.g. OpenAI or SentenceTransformers) are computationally expensive and require heavy frameworks (PyTorch). MD5-hashing tokens into a fixed-dimensional array with log-scaling frequency (`1.0 + log(count)`) simulates vector searches locally in pure Python with no dependencies.
