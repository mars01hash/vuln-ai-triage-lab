# Storage & Vulnerability Memory Module

This component maintains a vector-like in-memory database of triaged findings, backing it up to a JSON file to preserve deduplication states between runs.

## Files
* `memory_store.py`: Persistent database manager and deduplication engine.

## Python Usage
```python
from app.storage.memory_store import VulnerabilityMemory

# Initialize database pointing to file path
memory = VulnerabilityMemory(similarity_threshold=0.82, memory_path="output/memory.json")

# Checks similarity and records new entry
group_id, duplicate_of, similarity = memory.find_or_add(finding, canonical_cwe)

if duplicate_of:
    print(f"Duplicate of {duplicate_of} found in group {group_id}")
else:
    print(f"New vulnerability group spawned: {group_id}")
```

## Why it works
Filing duplicate scanner reports is a waste of AppSec developer resources. By hashing findings and persisting them to a JSON array file, the system keeps organizational memory alive, preventing duplicate triage requests across multiple pipeline runs.
