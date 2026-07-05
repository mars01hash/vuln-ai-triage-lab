# Threat Intelligence Module

This component enriches vulnerability findings with exploitability signals, such as threat intelligence flags and CISA KEV (Known Exploited Vulnerabilities) indicators, prior to risk prioritization.

## Files
* `enrichment.py`: Threat intelligence loader and enrichment engine.

## Python Usage
```python
from app.threat_intel.enrichment import enrich_finding_with_threat_intel

# Modifies finding raw payload to include exploit metrics
signal = enrich_finding_with_threat_intel(finding, canonical_cwe="CWE-89")
print(f"Exploit Likelihood: {signal['exploit_likelihood']} (Wild Exploited: {signal['exploited_in_wild']})")
```

## Why it works
CVSS severity is static and does not reflect real-world threat activity. By enriching findings with active threat feeds (like EPSS or CISA KEV), the pipeline deprioritizes low-probability vulnerabilities and escalates items that are being actively exploited in the wild.
