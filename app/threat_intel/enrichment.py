from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.schemas import VulnerabilityFinding

DEFAULT_THREAT_INTEL_PATH = Path("data/threat_intel_signals.json")


def load_threat_intel(path: str | Path = DEFAULT_THREAT_INTEL_PATH) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {"cwe_signals": {}, "package_signals": {}}
    return json.loads(p.read_text(encoding="utf-8"))


def enrich_finding_with_threat_intel(
    finding: VulnerabilityFinding,
    canonical_cwe: str,
    threat_intel_path: str | Path = DEFAULT_THREAT_INTEL_PATH,
) -> dict[str, Any]:
    """Attach lightweight threat intelligence signals to the finding.

    This is an MVP enrichment layer. In production, replace with EPSS, KEV,
    exploit DB/vendor intelligence, and internal incident telemetry.
    """
    intel = load_threat_intel(threat_intel_path)
    cwe_signal = intel.get("cwe_signals", {}).get(canonical_cwe, {})
    package_signal = {}
    if finding.package:
        package_signal = intel.get("package_signals", {}).get(finding.package.lower(), {}) or intel.get("package_signals", {}).get(finding.package, {})

    candidates = [signal for signal in (cwe_signal, package_signal) if signal]
    if not candidates:
        signal = {
            "exploit_likelihood": 0.5,
            "exploited_in_wild": False,
            "reason": "No explicit threat-intelligence signal found in local MVP dataset.",
            "source": "local_default",
        }
    else:
        # Use the strongest signal available.
        signal = max(candidates, key=lambda item: float(item.get("exploit_likelihood", 0.0))).copy()
        signal["source"] = "local_threat_intel_fixture"

    if signal.get("exploited_in_wild") or float(signal.get("exploit_likelihood", 0.0)) >= 0.85:
        finding.exploit_available = True

    finding.raw = dict(finding.raw or {})
    finding.raw["threat_intel"] = signal
    return signal
