# Storage & Vulnerability Memory Module

This component maintains a vector-like vulnerability memory of triaged findings, backing it up using either flat JSON files, SQLite databases, or ChromaDB.

## Files
* `memory_store.py`: Flat JSON-backed local storage database.
* `sqlite_vector_memory.py`: SQLite-backed vector database using JSON vector arrays.
* `chroma_memory_store.py`: Vector database using ChromaDB (requires `chromadb` package).

## Python Usage
Using SQLite vector memory:
```python
from app.storage.sqlite_vector_memory import SqliteVulnerabilityMemory

# DB creates table memory_records automatically
memory = SqliteVulnerabilityMemory(db_path="output/vulnerability_memory.sqlite")

# Inserts or finds duplicate
group_id, duplicate_of, similarity = memory.find_or_add(finding, canonical_cwe="CWE-89")
print(f"Group: {group_id}, Duplicate: {duplicate_of}")
```

Using Chroma vector memory:
```python
from app.storage.chroma_memory_store import ChromaVulnerabilityMemory

memory = ChromaVulnerabilityMemory(persist_dir="output/chroma_memory")
group_id, duplicate_of, similarity = memory.find_or_add(finding, canonical_cwe="CWE-89")
```

## Why it works
In large-scale security operations, duplicate findings from recurring scans clog developer backlogs. By encoding findings into vectors and calculating similarity against SQLite or Chroma collections, the pipeline deduplicates matches persistently.
