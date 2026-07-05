# v5 Architecture Design Notes

v5 upgrades the project from a scanner-driven portfolio prototype into a more evaluation-aware AppSec AI lab.

## Main additions

1. **CWE calibration metrics**
   - Accuracy and macro-F1 are not enough for this role.
   - v5 adds confidence bucket analysis, multiclass Brier score, and expected calibration error.

2. **Threat intelligence enrichment**
   - The scoring layer now receives a local exploit-likelihood signal.
   - In production, this should be replaced with EPSS, CISA KEV, commercial intel, and internal incident telemetry.

3. **Callgraph-style reachability fixture**
   - v5 includes a lightweight `data/callgraph_routes.json` fixture.
   - This simulates how CodeQL/Joern/callgraph evidence can feed the reachability gate.

4. **Human feedback retraining loop**
   - Feedback can be logged through the API and converted into augmented CWE training data.
   - This demonstrates how reviewer corrections can become future model training examples.

5. **Audit log**
   - CLI can write append-only JSONL decision records.
   - This is useful for explaining how outputs could be made auditable in regulated contexts.

6. **MCP-style tool contracts**
   - v5 exposes local tool contracts that mirror how an MCP server could expose normalization and enrichment tools.
   - The default install avoids a hard MCP runtime dependency.

## Design principle

The system keeps safety-sensitive decisions outside the LLM. LLM/agent outputs may explain and recommend, but WAF eligibility, human approval, reachability, and scoring are enforced by deterministic system logic.
