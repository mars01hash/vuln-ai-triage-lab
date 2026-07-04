# Ingestion Module

This component parses and validates raw inputs from heterogeneous security scanning tools (SAST, DAST, SCA) into standard canonical models.

## Files
* `adapters.py`: Entry point for parsing scanner findings lists.

## Python Usage
```python
from app.ingestion.adapters import parse_generic_findings

raw_payload = [
    {
        "finding_id": "SAST-001",
        "source_type": "SAST",
        "title": "SQL Injection",
        "description": "User input reaches raw SQL",
        "cvss": 8.8
    }
]

findings = parse_generic_findings(raw_payload)
print(findings[0].finding_id)  # "SAST-001"
```

## Why it works
Security scanning tools output heavily fragmented schemas. Ingestion adapters map tools to a unified data contract (`VulnerabilityFinding`), enabling downstream components (scoring, deduplication, patching) to execute on a single predictable interface.
