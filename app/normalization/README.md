# Normalization Module

This component maps free-text findings to standardized CWE weaknesses and extracts metadata entities like parameters, files, and endpoints.

## Files
* `cwe_classifier.py`: Rule-based keyword CWE mapper and confidence scorer.
* `entity_extractor.py`: Regular expressions scanner for parameters, endpoints, packages, and file paths.

## Python Usage
```python
from app.normalization.cwe_classifier import classify_cwe
from app.normalization.entity_extractor import extract_entities

# Mapped using keyword definitions
cwe, name, confidence, evidence = classify_cwe(finding)
print(f"Detected: {cwe} ({name}) with confidence {confidence}")

# Variables extracted using Regex
entities = extract_entities(finding, cwe)
print(f"Endpoint: {entities.endpoint}, Parameter: {entities.parameter}")
```

## Why it works
Raw report texts vary drastically. A local rule-based keyword classifier combined with regular expressions provides a zero-latency, zero-cost classification baseline without needing external API dependencies or GPU runtime.
