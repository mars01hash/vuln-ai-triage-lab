from __future__ import annotations

import sys
from pathlib import Path

# Add project root directory to python path to avoid ModuleNotFoundError in Streamlit
project_root = str(Path(__file__).resolve().parent.parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import json
from typing import Any

import pandas as pd
import streamlit as st

from app.ingestion.adapters import parse_generic_findings
from app.pipeline import TriagePipeline
from app.reporting.report_writer import write_markdown_report
from app.storage.sqlite_vector_memory import SqliteVulnerabilityMemory

st.set_page_config(page_title="Vulnerability AI Triage Lab v5", layout="wide")
st.title("🔐 Vulnerability AI Triage Lab v5")

st.caption("Scanner findings → CWE normalization → memory deduplication → priority scoring → human-reviewable triage")

DEFAULT_INPUT = Path("output/scanner_findings_all.json")
SAMPLE_INPUT = Path("data/sample_findings_all.json")
MEMORY_PATH = Path("output/dashboard_memory.sqlite")
REPORT_PATH = Path("output/dashboard_report.md")


def _load_json_file(path: Path) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))


def _risk_badge_order(risk: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(risk, 9)


def _to_dataframe(results) -> pd.DataFrame:
    rows = []
    for r in results:
        rows.append({
            "finding_id": r.finding_id,
            "source": r.source_type.value,
            "tool": r.tool_name,
            "asset": r.asset,
            "cwe": r.canonical_cwe,
            "cwe_name": r.cwe_name,
            "risk": r.risk_level,
            "score": r.priority_score,
            "reachable": r.reachable,
            "duplicate_of": r.duplicate_of or "",
            "waf_allowed": r.waf_rule_allowed,
            "approval_actions": ", ".join(r.approval_required_actions),
            "decision": r.triage_decision,
        })
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    df["risk_order"] = df["risk"].map(_risk_badge_order)
    return df.sort_values(["risk_order", "score"], ascending=[True, False]).drop(columns=["risk_order"])


with st.sidebar:
    st.header("Run Settings")
    use_ml = st.checkbox("Use trained ML CWE classifier", value=False)
    use_llm = st.checkbox("Use optional LLM triage", value=False)
    input_mode = st.radio("Input source", ["Scanner fixture output", "Sample findings", "Upload JSON"], index=0)
    st.info("Generate scanner fixture output with: python -m app.scanners.run_all")

payload: list[dict[str, Any]]
if input_mode == "Upload JSON":
    uploaded = st.file_uploader("Upload canonical findings JSON", type=["json"])
    if not uploaded:
        st.stop()
    payload = json.loads(uploaded.read().decode("utf-8"))
elif input_mode == "Scanner fixture output" and DEFAULT_INPUT.exists():
    payload = _load_json_file(DEFAULT_INPUT)
else:
    payload = _load_json_file(SAMPLE_INPUT)

findings = parse_generic_findings(payload)
memory = SqliteVulnerabilityMemory(db_path=MEMORY_PATH)
pipeline = TriagePipeline(memory=memory, use_ml_classifier=use_ml, use_llm_agent=use_llm, memory_backend_name="sqlite_vector_memory")
results = pipeline.process_many(findings)
df = _to_dataframe(results)

if df.empty:
    st.warning("No findings loaded.")
    st.stop()

critical = int((df["risk"] == "critical").sum())
high = int((df["risk"] == "high").sum())
duplicates = int((df["duplicate_of"] != "").sum())
waf_allowed = int(df["waf_allowed"].sum())

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Total Findings", len(df))
c2.metric("Critical", critical)
c3.metric("High", high)
c4.metric("Duplicates", duplicates)
c5.metric("WAF Proposals", waf_allowed)

st.subheader("Findings Table")
st.dataframe(df, use_container_width=True)

left, right = st.columns(2)
with left:
    st.subheader("Risk Distribution")
    st.bar_chart(df["risk"].value_counts())
with right:
    st.subheader("CWE Distribution")
    st.bar_chart(df["cwe"].value_counts())

st.subheader("Triage Details")
selected_id = st.selectbox("Select finding", df["finding_id"].tolist())
selected = next(r for r in results if r.finding_id == selected_id)
st.markdown(f"**{selected.title}**")
st.write(selected.reasoning_summary)
st.markdown("**Recommended Fix**")
st.write(selected.recommended_fix)
st.markdown("**Safety Notes**")
st.write(selected.safety_notes or ["No safety notes."])
st.markdown("**Proposed WAF Rule**")
st.code(selected.proposed_waf_rule or "No WAF rule allowed/proposed.")

if st.button("Write Markdown Report"):
    write_markdown_report(results, REPORT_PATH)
    st.success(f"Report written to {REPORT_PATH}")

st.subheader("Raw Selected Result")
st.json(selected.model_dump(mode="json"))
