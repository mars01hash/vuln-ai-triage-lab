# Audit Logging Module

This component captures final pipeline decisions and writes them to an append-only JSONL log file to support regulatory compliance and model validation audits.

## Files
* `audit_logger.py`: Compliance audit log recorder.

## Python Usage
```python
from app.audit.audit_logger import write_audit_log

# Appends normalized decision records to target file
summary = write_audit_log(results, output_path="output/v5_audit_log.jsonl")
print(f"Appended {summary['records_appended']} compliance records.")
```

## Why it works
In enterprise security operations, automated routing decisions must be explainable and auditable. Logging the exact ML prediction confidence, reachability logic, priority score weights, and WAF proposal triggers provides a clear forensic record of the automated triage workflow.
