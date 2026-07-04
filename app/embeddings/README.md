# Embeddings Module

This component tokenizes finding metadata texts into vector representations using SHA256 hashed bag-of-words or Sentence-Transformers.

## Files
* `providers.py`: Embedding providers and builder interface.

## Python Usage
Using Hash Embedding Provider:
```python
from app.embeddings.providers import build_embedding_provider

embedder = build_embedding_provider("hash")
vector = embedder.encode("Potential SQL injection on /api/orders")
print(f"Vector Dimensions: {len(vector)} (Hashed SHA256)")
```

Using Sentence-Transformers (requires `sentence-transformers` package):
```python
from app.embeddings.providers import build_embedding_provider

embedder = build_embedding_provider("sentence-transformer", model_name="all-MiniLM-L6-v2")
vector = embedder.encode("Potential SQL injection on /api/orders")
print(f"Vector Dimensions: {len(vector)} (Neural network)")
```

## Why it works
The `EmbeddingProvider` interface abstracts vector generation from the database. It allows testing and running the pipeline offline using the lightweight SHA256 signer, while retaining the ability to swap in deep learning models for high-quality semantic mapping.
