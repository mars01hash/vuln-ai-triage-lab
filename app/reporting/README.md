# Reporting Module

This component generates an executive-level Markdown summary report from a list of pipeline triage results.

## Files
* `report_writer.py`: Markdown file report writer.

## Python Usage
```python
from app.reporting.report_writer import write_markdown_report

# Writes batch metrics tables and prioritized assets info
write_markdown_report(results, "output/batch_report.md")
```

## Why it works
Raw JSON outputs from security pipelines are difficult to consume in bulk. A batch report writer groups findings by risk level, CWE, exposure channels, and assets, converting raw technical data into readable tables for business meetings.
