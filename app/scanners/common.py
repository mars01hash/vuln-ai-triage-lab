from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


def read_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path: str | Path, payload: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def run_command(command: list[str], cwd: str | Path | None = None, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        timeout=timeout,
        text=True,
        capture_output=True,
        check=False,
    )


def severity_to_cvss(severity: str | None, default: float = 5.0) -> float:
    sev = (severity or "").lower()
    if sev in {"critical", "error", "blocker"}:
        return 9.0
    if sev in {"high"}:
        return 8.0
    if sev in {"medium", "warning"}:
        return 6.0
    if sev in {"low", "info", "informational", "note"}:
        return 3.0
    return default


def zap_risk_to_cvss(risk: str | None) -> float:
    risk = (risk or "").lower()
    if "high" in risk:
        return 8.5
    if "medium" in risk:
        return 6.5
    if "low" in risk:
        return 3.5
    return 5.0


def cwe_to_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text in {"0", "-1"}:
        return None
    if text.upper().startswith("CWE-"):
        return text.upper()
    if text.isdigit():
        return f"CWE-{text}"
    return text
