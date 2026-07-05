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

try:
    import plotly.express as px
    import plotly.graph_objects as go
    HAS_PLOTLY = True
except ImportError:
    HAS_PLOTLY = False

from app.ingestion.adapters import parse_generic_findings
from app.pipeline import TriagePipeline
from app.reporting.report_writer import write_markdown_report
from app.storage.sqlite_vector_memory import SqliteVulnerabilityMemory
from app.feedback.feedback_store import FeedbackStore
from app.schemas import TriageFeedback

st.set_page_config(
    page_title="VULN_AI_TRIAGE::TERMINAL_V5",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom hacker/terminal styling CSS
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
    
    html, body, [class*="css"], div, span, button, input, select, textarea {
        font-family: 'Share Tech Mono', monospace !important;
    }
    
    /* Set dark terminal theme on app canvas, headers, sidebars */
    .stApp, [data-testid="stAppViewContainer"], [data-testid="stHeader"], [data-testid="stSidebar"] {
        font-family: 'Share Tech Mono', monospace !important;
        background-color: #05080C !important;
    }
    
    /* Apply terminal font & color to text nodes, metrics, and markdown */
    h1, h2, h3, h4, h5, h6, p, label, .stMarkdown, .stText, [data-testid="stWidgetLabel"] p, .stAlert p {
        font-family: 'Share Tech Mono', monospace !important;
        color: #00FF66 !important;
    }
    
    /* Apply style to form control elements */
    input, select, textarea, button, button p {
        font-family: 'Share Tech Mono', monospace !important;
        color: #00FF66 !important;
    }
    
    /* Terminal Table Styling */
    table {
        width: 100% !important;
        border-collapse: collapse !important;
        border: 1px dashed #00AA44 !important;
        margin-bottom: 25px !important;
        background-color: #03060A !important;
    }
    
    tr {
        border-bottom: 1px dashed #00AA44 !important;
    }
    
    tr:hover {
        background-color: #081017 !important;
    }
    
    th {
        background-color: #08121A !important;
        color: #00FFFF !important;
        padding: 10px 12px !important;
        text-align: left !important;
        border-right: 1px dashed #00AA44 !important;
        font-weight: bold !important;
        text-transform: uppercase !important;
    }
    
    td {
        padding: 10px 12px !important;
        border-right: 1px dashed #00AA44 !important;
        color: #00FF66 !important;
        background-color: transparent !important;
    }
    
    /* Terminal titles */
    .secops-title {
        font-size: 34px;
        font-weight: 700;
        color: #00FF66 !important;
        margin-bottom: 2px;
        letter-spacing: 0.05em;
        text-shadow: 0 0 10px rgba(0, 255, 102, 0.4);
    }
    
    .secops-subtitle {
        font-size: 14px;
        color: #00AA44 !important;
        margin-bottom: 25px;
        border-left: 2px dashed #00FF66;
        padding-left: 10px;
        letter-spacing: 0.02em;
    }

    /* Terminal metrics cards styling (Dashed Cyber Box) */
    .metric-grid {
        display: grid;
        grid-template-columns: repeat(5, 1fr);
        gap: 20px;
        margin-bottom: 25px;
    }

    .metric-card {
        position: relative;
        background-color: #080C12 !important;
        border: 1px dashed #00AA44 !important;
        padding: 20px;
        border-radius: 0px !important; /* Strict rectangular terminal geometry */
        transition: all 0.2s ease-in-out;
        text-align: center;
    }
    
    .metric-card:hover {
        border-color: #00FF66 !important;
        box-shadow: 0 0 15px rgba(0, 255, 102, 0.25);
    }

    .metric-critical {
        border: 1px dashed #FF0033 !important;
    }
    .metric-critical .metric-value {
        color: #FF0033 !important;
        text-shadow: 0 0 10px rgba(255, 0, 51, 0.5);
    }
    .metric-critical .metric-label {
        color: #CC0022 !important;
    }

    .metric-high {
        border: 1px dashed #FF8800 !important;
    }
    .metric-high .metric-value {
        color: #FF8800 !important;
    }

    .metric-waf {
        border: 1px dashed #00FFFF !important;
    }
    .metric-waf .metric-value {
        color: #00FFFF !important;
    }
    .metric-waf .metric-label {
        color: #00AAAA !important;
    }
    
    .metric-label {
        color: #00AA44;
        font-weight: 700;
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-bottom: 8px;
    }
    
    .metric-value {
        font-size: 38px;
        font-weight: 700;
        color: #00FF66;
    }
    
    /* Terminal Tabs Styling */
    button[data-baseweb="tab"] {
        font-size: 14px !important;
        font-weight: 700 !important;
        color: #00AA44 !important;
        background-color: #05080C !important;
        border-radius: 0px !important;
        text-transform: uppercase;
        border: 1px solid transparent !important;
        margin-right: 5px !important;
    }
    
    button[data-baseweb="tab"]:hover {
        color: #00FF66 !important;
        background-color: #0B111A !important;
    }
    
    button[data-baseweb="tab"][aria-selected="true"] {
        color: #06B6D4 !important;
        background-color: #080F18 !important;
        border: 1px dashed #00FF66 !important;
        border-bottom-color: #06B6D4 !important;
    }

    /* Severity badges */
    .badge {
        padding: 3px 8px;
        border: 1px solid transparent;
        font-weight: 700;
        font-size: 11px;
        text-transform: uppercase;
        display: inline-block;
        border-radius: 0px;
    }
    .badge:hover {
        transform: scale(1.08);
        box-shadow: 0 0 8px rgba(255, 255, 255, 0.15);
    }
    .badge-critical { border-color: #FF0033; color: #FF0033 !important; background-color: rgba(255, 0, 51, 0.05) !important; }
    .badge-high { border-color: #FF8800; color: #FF8800 !important; background-color: rgba(255, 136, 0, 0.05) !important; }
    .badge-medium { border-color: #FFFF00; color: #FFFF00 !important; background-color: rgba(255, 255, 0, 0.05) !important; }
    .badge-low { border-color: #00FF66; color: #00FF66 !important; background-color: rgba(0, 255, 102, 0.05) !important; }

    /* Custom Terminal Blocks */
    .terminal-block {
        background-color: #03060A !important;
        border: 1px dashed #00AA44 !important;
        padding: 15px;
        margin-bottom: 20px;
        line-height: 1.6;
        font-size: 13px;
    }
    
    .terminal-block-critical {
        border-color: #FF0033 !important;
        color: #FF5555 !important;
        background-color: #0D0507 !important;
    }
    .terminal-block-critical * {
        color: #FF5555 !important;
        background-color: #0D0507 !important;
    }
    
    .terminal-block-success {
        border-color: #00FFFF !important;
        color: #55FFFF !important;
        background-color: #030A0E !important;
    }
    .terminal-block-success * {
        color: #55FFFF !important;
        background-color: #030A0E !important;
    }
    
    /* Style all buttons in the cockpit columns */
    [data-testid="column"] button, button[data-testid="stBaseButton-secondary"] {
        background-color: #08121A !important;
        border: 1px solid #00FF66 !important;
        color: #00FF66 !important;
        font-family: 'Share Tech Mono', monospace !important;
        font-weight: bold !important;
        border-radius: 0px !important;
        text-transform: uppercase !important;
        width: 100% !important;
        transition: all 0.2s ease-in-out !important;
    }
    
    [data-testid="column"] button:hover, button[data-testid="stBaseButton-secondary"]:hover {
        background-color: #00FF66 !important;
        color: #03060A !important;
        box-shadow: 0 0 15px rgba(0, 255, 102, 0.4) !important;
    }
    
    /* Form containment cockpit overrides */
    form[data-testid="stForm"] {
        background-color: #080C12 !important;
        border: 1px dashed #00AA44 !important;
        border-radius: 0px !important;
        padding: 20px !important;
    }
    
    /* Interactive input fields terminal style */
    input, select, textarea, [data-baseweb="select"] {
        background-color: #03060A !important;
        color: #00FF66 !important;
        border: 1px solid #00AA44 !important;
        border-radius: 0px !important;
    }
    
    input:focus, select:focus, textarea:focus {
        border-color: #00FF66 !important;
        box-shadow: 0 0 5px rgba(0, 255, 102, 0.4) !important;
    }
    
    /* Submit button execution console styling */
    [data-testid="stForm"] button, button[data-testid="stFormSubmitButton"] {
        background-color: #08121A !important;
        border: 1px solid #00FF66 !important;
        color: #00FF66 !important;
        font-weight: bold !important;
        border-radius: 0px !important;
        text-transform: uppercase !important;
        letter-spacing: 0.1em !important;
        width: 100% !important;
        transition: all 0.2s ease-in-out !important;
    }
    
    [data-testid="stForm"] button:hover {
        background-color: #00FF66 !important;
        color: #03060A !important;
        box-shadow: 0 0 15px rgba(0, 255, 102, 0.5) !important;
    }
    </style>
""", unsafe_allow_html=True)

# Layout Header Box
st.markdown("""
    <div style="background-color: #080C12; border: 1px dashed #00FF66; padding: 20px; margin-bottom: 25px; position: relative;">
        <div class="secops-title">[SYS_SEC::THREAT_COMMAND_V5.0]</div>
        <div style="font-size: 12px; font-weight: 700; color: #00AA44; text-transform: uppercase; letter-spacing: 0.1em; display: flex; align-items: center; gap: 8px;">
            <span style="display: inline-block; width: 6px; height: 6px; background-color: #00FF66; border-radius: 50%; animation: pulseStatus 1s infinite;"></span>
            STATUS: ACTIVE_TRIAGE_GATES_ENGAGED // SCANNERS: INGESTING // THREAT_INTEL: AGGREGATING
        </div>
    </div>
""", unsafe_allow_html=True)

DEFAULT_INPUT = Path("output/scanner_findings_all.json")
SAMPLE_INPUT = Path("data/sample_findings_all.json")
MEMORY_PATH = Path("output/dashboard_memory.sqlite")
REPORT_PATH = Path("output/dashboard_report.md")
CALIBRATION_PATH = Path("output/v5_cwe_calibration_metrics.json")
FEEDBACK_PATH = Path("output/api_human_feedback.jsonl")

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

def style_terminal_table(df: pd.DataFrame):
    display_df = df[["finding_id", "risk", "cwe", "source", "reachable", "score", "decision"]].copy()
    display_df["risk"] = display_df["risk"].str.upper()
    display_df["source"] = display_df["source"].str.upper()
    display_df["reachable"] = display_df["reachable"].map(lambda x: "TRUE" if x else "FALSE")
    display_df["score"] = display_df["score"].map(lambda x: f"{x:.3f}")
    display_df["decision"] = display_df["decision"].str.upper()
    
    def _color_cells(val):
        if val == "CRITICAL":
            return "color: #FF0033 !important; font-weight: bold !important;"
        elif val == "HIGH":
            return "color: #FF8800 !important; font-weight: bold !important;"
        elif val == "MEDIUM":
            return "color: #FFFF00 !important; font-weight: bold !important;"
        elif val == "LOW":
            return "color: #00FF66 !important; font-weight: bold !important;"
        elif val == "TRUE":
            return "color: #00FF66 !important; font-weight: bold !important;"
        elif val == "FALSE":
            return "color: #888888 !important; font-weight: bold !important;"
        return "color: #00FF66 !important;"
        
    display_df = display_df.rename(columns={
        "finding_id": "[ID]",
        "risk": "[RISK]",
        "cwe": "[CWE]",
        "source": "[SRC]",
        "reachable": "[REACHABLE]",
        "score": "[SCORE]",
        "decision": "[DECISION]"
    })
    return display_df.style.map(_color_cells)

def style_reliability_table(bin_list: list[dict[str, Any]]):
    bin_df = pd.DataFrame(bin_list)
    display_df = pd.DataFrame({
        "[BIN_RANGE]": bin_df.apply(lambda r: f"{r['bin_low']:.1f} - {r['bin_high']:.1f}", axis=1),
        "[COUNT]": bin_df["count"],
        "[CONFIDENCE]": bin_df["confidence"].map(lambda x: f"{x:.4f}"),
        "[ACCURACY]": bin_df["accuracy"].map(lambda x: f"{x:.4f}"),
        "[GAP]": bin_df["gap"].map(lambda x: f"{x:.4f}")
    })
    
    def _color_gap(val):
        try:
            v = float(val)
            if v > 0.3:
                return "color: #FF8800 !important; font-weight: bold !important;"
        except:
            pass
        return "color: #00FF66 !important;"
        
    return display_df.style.map(_color_gap)

def _render_plotly_scatter(df: pd.DataFrame):
    fig = px.scatter(
        df,
        x="score",
        y="risk",
        color="source",
        size="score",
        hover_data=["finding_id", "cwe"],
        category_orders={"risk": ["critical", "high", "medium", "low"]}
    )
    fig.update_layout(
        font_family="Share Tech Mono",
        font_color="#00FF66",
        paper_bgcolor="#05080C",
        plot_bgcolor="#05080C",
        xaxis=dict(
            title="RISK_SCORE",
            gridcolor="#00220A",
            zerolinecolor="#00220A",
            linecolor="#00AA44",
            tickfont=dict(family="Share Tech Mono", color="#00FF66")
        ),
        yaxis=dict(
            title="VECTOR_SEVERITY",
            gridcolor="#00220A",
            zerolinecolor="#00220A",
            linecolor="#00AA44",
            tickfont=dict(family="Share Tech Mono", color="#00FF66")
        ),
        legend=dict(
            font=dict(family="Share Tech Mono", color="#00FF66"),
            bgcolor="#080C12",
            bordercolor="#00AA44",
            borderwidth=1
        ),
        margin=dict(l=40, r=40, t=20, b=40)
    )
    fig.update_traces(
        marker=dict(line=dict(width=1, color='#00FF66'))
    )
    return fig

def _render_plotly_bar(series: pd.Series, title_text: str, color_hex: str):
    max_val = int(series.max()) if not series.empty else 10
    y_max = max(1, int(max_val * 1.25))

    fig = go.Figure(go.Bar(
        x=series.index,
        y=series.values,
        text=series.values,
        textposition="outside",
        textfont=dict(family="Share Tech Mono", size=11, color="#00FF66"),
        marker_color=color_hex,
        marker_line_color="#00FF66",
        marker_line_width=1.5,
        hovertemplate="[VAL: %{y} // BIN: %{x}]<extra></extra>"
    ))
    fig.update_layout(
        title=dict(
            text=f"&gt; {title_text}",
            font=dict(family="Share Tech Mono", size=13, color="#00FFFF"),
            x=0.05,
            y=0.92,
            yref="container",
            yanchor="top"
        ),
        font_family="Share Tech Mono",
        font_color="#00FF66",
        paper_bgcolor="#05080C",
        plot_bgcolor="#05080C",
        xaxis=dict(
            tickangle=45,
            gridcolor="#00220A",
            linecolor="#00AA44",
            tickfont=dict(family="Share Tech Mono", size=10, color="#00FF66"),
            automargin=False
        ),
        yaxis=dict(
            range=[0, y_max],
            gridcolor="#00220A",
            linecolor="#00AA44",
            tickfont=dict(family="Share Tech Mono", size=10, color="#00FF66"),
            automargin=False
        ),
        margin=dict(l=35, r=10, t=55, b=110),
        height=280,
        autosize=True
    )
    fig.update_traces(cliponaxis=False)
    return fig

def _render_plotly_histogram(series: pd.Series, title_text: str, color_hex: str):
    fig = go.Figure(go.Histogram(
        x=series,
        nbinsx=10,
        marker_color=color_hex,
        marker_line_color="#00FF66",
        marker_line_width=1.5,
        hovertemplate="[FREQ: %{y} // SCORE_RANGE: %{x}]<extra></extra>"
    ))
    fig.update_layout(
        title=dict(
            text=f"&gt; {title_text}",
            font=dict(family="Share Tech Mono", size=13, color="#00FFFF"),
            x=0.05,
            y=0.92,
            yref="container",
            yanchor="top"
        ),
        font_family="Share Tech Mono",
        font_color="#00FF66",
        paper_bgcolor="#05080C",
        plot_bgcolor="#05080C",
        xaxis=dict(
            title="VALUE_RANGE",
            gridcolor="#00220A",
            linecolor="#00AA44",
            tickfont=dict(family="Share Tech Mono", size=10, color="#00FF66"),
            automargin=False
        ),
        yaxis=dict(
            title="FREQUENCY",
            gridcolor="#00220A",
            linecolor="#00AA44",
            tickfont=dict(family="Share Tech Mono", size=10, color="#00FF66"),
            automargin=False
        ),
        margin=dict(l=35, r=10, t=55, b=110),
        height=280,
        autosize=True
    )
    return fig

def _render_calibration_curve(bin_list: list[dict[str, Any]]):
    bin_df = pd.DataFrame(bin_list)
    bin_df = bin_df.sort_values("bin_low")
    
    fig = go.Figure()
    
    # Perfect calibration line
    fig.add_trace(go.Scatter(
        x=[0, 1],
        y=[0, 1],
        mode="lines",
        name="PERFECT_CALIBRATION",
        line=dict(color="#888888", dash="dash", width=1.5),
        hovertemplate="PERFECT: %{x}<extra></extra>"
    ))
    
    # Model calibration line
    fig.add_trace(go.Scatter(
        x=bin_df["confidence"],
        y=bin_df["accuracy"],
        mode="lines+markers",
        name="TRIAGE_MODEL_V5",
        line=dict(color="#00FF66", width=2),
        marker=dict(size=8, color="#00FFFF", symbol="cross"),
        hovertemplate="CONF: %{x:.4f}<br>ACC: %{y:.4f}<extra></extra>"
    ))
    
    fig.update_layout(
        title=dict(
            text="&gt; MODEL_RELIABILITY_CURVE",
            font=dict(family="Share Tech Mono", size=13, color="#00FFFF"),
            x=0.05,
            y=0.92,
            yref="container",
            yanchor="top"
        ),
        font_family="Share Tech Mono",
        font_color="#00FF66",
        paper_bgcolor="#05080C",
        plot_bgcolor="#05080C",
        xaxis=dict(
            title="MEAN_CONFIDENCE",
            gridcolor="#00220A",
            linecolor="#00AA44",
            tickfont=dict(family="Share Tech Mono", size=10, color="#00FF66"),
            range=[0, 1],
            automargin=False
        ),
        yaxis=dict(
            title="EMPIRICAL_ACCURACY",
            gridcolor="#00220A",
            linecolor="#00AA44",
            tickfont=dict(family="Share Tech Mono", size=10, color="#00FF66"),
            range=[0, 1],
            automargin=False
        ),
        legend=dict(
            font=dict(family="Share Tech Mono", size=10, color="#00FF66"),
            bgcolor="#080C12",
            bordercolor="#00AA44",
            borderwidth=1,
            x=0.05,
            y=0.85
        ),
        margin=dict(l=40, r=10, t=55, b=55),
        height=300,
        autosize=True
    )
    return fig

# Sidebar configurations
with st.sidebar:
    st.header("PIPELINE_CONFIG")
    use_ml = st.checkbox("Enable Trained ML Classifier (v5)", value=True)
    use_llm = st.checkbox("Enable Optional OpenAI LLM", value=False)
    input_mode = st.radio("Input Source Mode", ["Aggregated Scanner Output", "Sample Findings", "Upload JSON Findings"], index=0)
    
    st.markdown("---")
    st.markdown("### BACKEND_STATUS")
    st.info("System uses SQLite vector memory and exploit threat database filters to deduplicate findings.")

# Input Payload Loader
payload: list[dict[str, Any]]
if input_mode == "Upload JSON Findings":
    uploaded = st.file_uploader("Upload canonical findings JSON", type=["json"])
    if not uploaded:
        st.stop()
    payload = json.loads(uploaded.read().decode("utf-8"))
elif input_mode == "Aggregated Scanner Output" and DEFAULT_INPUT.exists():
    payload = _load_json_file(DEFAULT_INPUT)
else:
    payload = _load_json_file(SAMPLE_INPUT)

# Process findings through the Orchestrator Pipeline
findings = parse_generic_findings(payload)
memory = SqliteVulnerabilityMemory(db_path=MEMORY_PATH)
pipeline = TriagePipeline(
    memory=memory, 
    use_ml_classifier=use_ml, 
    use_llm_agent=use_llm, 
    memory_backend_name="sqlite_vector_memory"
)
results = pipeline.process_many(findings)
df = _to_dataframe(results)

if df.empty:
    st.warning("No findings loaded.")
    st.stop()

# Metric Calculations
total_findings = len(df)
critical = int((df["risk"] == "critical").sum())
high = int((df["risk"] == "high").sum())
duplicates = int((df["duplicate_of"] != "").sum())
waf_allowed = int(df["waf_allowed"].sum())

# Metrics Grid (Cyber Brackets)
st.markdown(f"""
    <div class="metric-grid">
        <div class="metric-card">
            <div class="metric-label">Ingest Registry</div>
            <div class="metric-value">{total_findings}</div>
        </div>
        <div class="metric-card metric-critical">
            <div class="metric-label">Breach Alerts</div>
            <div class="metric-value">{critical}</div>
        </div>
        <div class="metric-card metric-high">
            <div class="metric-label">Priority Vectors</div>
            <div class="metric-value">{high}</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Semantic Clusters</div>
            <div class="metric-value">{duplicates}</div>
        </div>
        <div class="metric-card metric-waf">
            <div class="metric-label">Active Shields</div>
            <div class="metric-value">{waf_allowed}</div>
        </div>
    </div>
""", unsafe_allow_html=True)

st.markdown("---")

# Main Operations Cockpit Tabs (Matrix terminal style)
t1, t2, t3, t4 = st.tabs(["SYS_ANALYTICS", "VULNERABILITY_EXPLORER", "CALIBRATION_DIAGNOSTICS", "FEEDBACK_INTEGRATION"])

# --- TAB 1: Analytics Overview ---
with t1:
    st.subheader("CWE_THREAT_INTELLIGENCE_METRICS")
    
    # Tactical Terminal Telemetry Report Block
    st.markdown(f"""
        <div class="terminal-block">
            <span style="color: #64748B;">[SYSTEM LOG - REALTIME TELEMETRY DATA DUMP]</span><br/>
            &gt;&gt;&gt; INGESTED_THREATS_COUNT: {total_findings}<br/>
            &gt;&gt;&gt; ACTIVE_CRITICAL_BREACHES: {critical} // FLAG: FLASHING_ALERT_ACTIVE<br/>
            &gt;&gt;&gt; HIGH_RISK_EXPLOIT_VECTORS: {high}<br/>
            &gt;&gt;&gt; DEDUPLICATED_ALERTS_MERGED: {duplicates}<br/>
            &gt;&gt;&gt; COMPILED_WAF_VIRTUAL_SHIELDS: {waf_allowed}<br/>
            &gt;&gt;&gt; PIPELINE_INTEGRITY_INDEX: 1.000 (SECURE)<br/>
            &gt;&gt;&gt; MEMORY_STORE: sqlite_vector_memory // DATA_DRIFT: STABLE
        </div>
    """, unsafe_allow_html=True)
    
    # Priority Clustering Chart Section
    st.markdown("""
        <div style="border-top: 1px dashed #00AA44; border-bottom: 1px dashed #00AA44; padding: 10px 0; margin-top: 20px; margin-bottom: 15px;">
            <span style="font-weight: bold; color: #00FFFF;">[SYS_ANALYTICS::MODULE_A // PRIORITY_CLUSTERING_SCATTER]</span>
        </div>
    """, unsafe_allow_html=True)
    
    if HAS_PLOTLY:
        st.plotly_chart(_render_plotly_scatter(df), use_container_width=True)
    else:
        st.scatter_chart(
            df,
            x="score",
            y="risk",
            color="source",
            size="score",
            use_container_width=True
        )
    
    # Distribution Charts Section
    st.markdown("""
        <div style="border-top: 1px dashed #00AA44; border-bottom: 1px dashed #00AA44; padding: 10px 0; margin-top: 20px; margin-bottom: 15px;">
            <span style="font-weight: bold; color: #00FFFF;">[SYS_ANALYTICS::MODULE_B // DISTRIBUTION_HISTOGRAMS]</span>
        </div>
    """, unsafe_allow_html=True)
    
    if HAS_PLOTLY:
        col1, col2, col3 = st.columns(3)
        with col1:
            st.plotly_chart(_render_plotly_bar(df["risk"].value_counts(), "RISK_LEVEL_DISTRIBUTION", "#FF0033"), use_container_width=True)
        with col2:
            st.plotly_chart(_render_plotly_bar(df["cwe"].value_counts(), "CWE_CATEGORIES_DISTRIBUTION", "#00FF66"), use_container_width=True)
        with col3:
            tool_counts = df["tool"].value_counts()
            tool_counts.index = tool_counts.index.map(lambda x: "OWASP Dep-Check" if x == "OWASP Dependency-Check" else x)
            st.plotly_chart(_render_plotly_bar(tool_counts, "SCANNER_CONTRIBUTION", "#00FFFF"), use_container_width=True)
    else:
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown("[METRICS::RISK_LEVEL_DISTRIBUTION]")
            st.bar_chart(df["risk"].value_counts(), color="#FF0033")
        with col2:
            st.markdown("[METRICS::CWE_CATEGORIES_DISTRIBUTION]")
            st.bar_chart(df["cwe"].value_counts(), color="#00FF66")
        with col3:
            st.markdown("[METRICS::SCANNER_CONTRIBUTION]")
            st.bar_chart(df["tool"].value_counts(), color="#00FFFF")

    # Mitigation and Reconciliation Charts Section (Module C)
    st.markdown("""
        <div style="border-top: 1px dashed #00AA44; border-bottom: 1px dashed #00AA44; padding: 10px 0; margin-top: 20px; margin-bottom: 15px;">
            <span style="font-weight: bold; color: #00FFFF;">[SYS_ANALYTICS::MODULE_C // MITIGATION_AND_RECONCILIATION]</span>
        </div>
    """, unsafe_allow_html=True)
    
    if HAS_PLOTLY:
        col4, col5, col6 = st.columns(3)
        with col4:
            reach_series = df["reachable"].map(lambda x: "REACHABLE" if x else "UNREACHABLE").value_counts()
            st.plotly_chart(_render_plotly_bar(reach_series, "CODE_REACHABILITY_STATUS", "#00FF66"), use_container_width=True)
        with col5:
            waf_series = df["waf_allowed"].map(lambda x: "WAF_ELIGIBLE" if x else "WAF_INELIGIBLE").value_counts()
            st.plotly_chart(_render_plotly_bar(waf_series, "VIRTUAL_PATCH_PROPOSALS", "#00FFFF"), use_container_width=True)
        with col6:
            st.plotly_chart(_render_plotly_histogram(df["score"], "PRIORITY_SCORE_DISTRIBUTION", "#FF8800"), use_container_width=True)
    else:
        col4, col5, col6 = st.columns(3)
        with col4:
            st.markdown("[METRICS::CODE_REACHABILITY_STATUS]")
            reach_series = df["reachable"].map(lambda x: "REACHABLE" if x else "UNREACHABLE").value_counts()
            st.bar_chart(reach_series, color="#00FF66")
        with col5:
            st.markdown("[METRICS::VIRTUAL_PATCH_PROPOSALS]")
            waf_series = df["waf_allowed"].map(lambda x: "WAF_ELIGIBLE" if x else "WAF_INELIGIBLE").value_counts()
            st.bar_chart(waf_series, color="#00FFFF")
        with col6:
            st.markdown("[METRICS::PRIORITY_SCORE_DISTRIBUTION]")
            st.bar_chart(df["score"], color="#FF8800")

# --- TAB 2: Vulnerability Explorer ---
with t2:
    st.subheader("PIPELINE_VULNERABILITY_REGISTRY")
    st.markdown("Parsed scanner threat telemetry database printout:")
    st.table(style_terminal_table(df))
    
    st.markdown("---")
    
    st.subheader("INSPECT::THREAT_VECTOR_TELEMETRY")
    selected_id = st.selectbox("Select finding_id to query", df["finding_id"].tolist())
    selected = next(r for r in results if r.finding_id == selected_id)
    
    badge_class = f"badge-{selected.risk_level}"
    badge_html = f'<span class="badge {badge_class}">{selected.risk_level}</span>'
    
    col_l, col_r = st.columns([2, 1])
    with col_l:
        st.markdown(f"""
            <div style="background-color: #080C12; border: 1px dashed #00FF66; padding: 20px; margin-bottom: 20px; position: relative;">
                <div style="font-size: 18px; font-weight: 700; color: #00FF66; margin-bottom: 8px;">TARGET: {selected.title} {badge_html}</div>
                <div style="color: #00AA44; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 12px;">
                    CWE: {selected.canonical_cwe} ({selected.cwe_name}) // TOOL: {selected.tool_name}
                </div>
                <div style="font-family: 'Share Tech Mono', monospace; color: #00FFFF; font-size: 13px; border-top: 1px dashed #00AA44; padding-top: 10px;">
                    EXECUTION STATUS: {selected.triage_decision.upper()}
                </div>
            </div>
        """, unsafe_allow_html=True)
        
        st.markdown("CWE_THREAT_REASONING_LOG")
        st.markdown(f"""
            <div class="terminal-block">
                <span>[SYSTEM LOG - THREAT ANALYSIS]</span><br/>
                &gt; Candidate CWE: {selected.canonical_cwe}<br/>
                &gt; Exploit Priority: {selected.priority_score:.3f} / 1.000<br/>
                &gt; Callgraph Verify: {"PASS" if selected.reachable else "FAIL"}<br/>
                &gt; Duplicate Link: {selected.duplicate_of or "N/A"}<br/>
                &gt; DETAILED ANALYSIS: {selected.reasoning_summary}
            </div>
        """, unsafe_allow_html=True)
        
        st.markdown("REMEDIATION_ACTION_PLAN")
        st.markdown(f"""
            <div class="terminal-block" style="border-color: #10B981 !important; color: #34D399 !important; background-color: #040A06 !important;">
                <span>[REMEDIATION PLAYBOOK]</span><br/>
                &gt; Core Instruction: {selected.recommended_fix}
            </div>
        """, unsafe_allow_html=True)
        
        st.markdown("SHIELD_VIRTUAL_PATCH_PROPOSAL")
        if selected.proposed_waf_rule:
            st.markdown("""
                <div style="background-color: #03060A; border: 1px dashed #00FF66; padding: 10px; margin-bottom: 10px; font-family: 'Share Tech Mono', monospace;">
                    <span style="color: #00FF66; font-weight: bold;">[VIRTUAL_PATCH::NGINX_MODSEC_RULE]</span>
                </div>
            """, unsafe_allow_html=True)
            st.code(selected.proposed_waf_rule, language="nginx")
        else:
            reason = selected.safety_notes[0] if selected.safety_notes else "Blocked by pipeline safety constraints."
            st.markdown(f"""
                <div class="terminal-block terminal-block-critical">
                    &gt; SHIELD WARNING: Virtual Patching signatures are not eligible for this threat vector.<br/>
                    &gt; REASON: {reason}
                </div>
            """, unsafe_allow_html=True)
            
    with col_r:
        st.markdown("METADATA_INDEX")
        st.markdown(f"""
            <div class="terminal-block">
                <span style="color: #64748B;">[METADATA_INDEX::DUMP]</span><br/>
                &gt; FINDING_ID: {selected.finding_id}<br/>
                &gt; TARGET_ASSET: {selected.asset}<br/>
                &gt; SCORE: {selected.priority_score:.4f}<br/>
                &gt; REACHABLE: {selected.reachable}<br/>
                &gt; REACH_REASON: {selected.reachability_reason or "N/A"}<br/>
                &gt; DUPLICATE_OF: {selected.duplicate_of or "NONE"}<br/>
                &gt; SIMILARITY: {selected.similarity_to_duplicate or 0.0:.2%}<br/>
                &gt; AGENT_MODE: {selected.agent_mode}<br/>
                &gt; MEMORY_STORE: {selected.memory_backend}<br/>
                &gt; REQ_APPROVAL: {", ".join(selected.approval_required_actions) or "NONE"}
            </div>
        """, unsafe_allow_html=True)
        
        st.markdown("SAFETY_ISOLATION_LOGS")
        safety_lines = "<br/>".join([f"&gt;&gt;&gt; {note}" for note in selected.safety_notes]) if selected.safety_notes else "&gt;&gt;&gt; NO SAFETY VIOLATIONS RECORDED // ISOLATION GATES CLEAR."
        st.markdown(f"""
            <div class="terminal-block" style="border-color: #00FFFF !important; color: #55FFFF !important; background-color: #030A0E !important;">
                <span style="color: #00FFFF;">[SAFETY_LOGS::TELEMETRY]</span><br/>
                {safety_lines}
            </div>
        """, unsafe_allow_html=True)
        
        st.markdown("REPORTS_EXPORTER")
        if st.button("Generate Executive Markdown Report"):
            write_markdown_report(results, REPORT_PATH)
            st.success(f"Report written to `{REPORT_PATH}`")

# --- TAB 3: Model Diagnostics ---
with t3:
    st.subheader("MODEL_CALIBRATION_DIAGNOSTICS")
    
    if not CALIBRATION_PATH.exists():
        st.warning("[WARNING::Calibration metrics unavailable]")
    else:
        cal = _load_json_file(CALIBRATION_PATH)
        
        # Custom Hacker Metric Cards for Calibration
        st.markdown(f"""
            <div class="metric-grid">
                <div class="metric-card">
                    <div class="metric-label">Accuracy</div>
                    <div class="metric-value">{cal['accuracy'] * 100:.1f}%</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Macro F1</div>
                    <div class="metric-value">{cal['macro_f1'] * 100:.1f}%</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Brier Score</div>
                    <div class="metric-value">{cal['brier_score_multiclass']:.4f}</div>
                </div>
                <div class="metric-card metric-waf">
                    <div class="metric-label">Calibration Error</div>
                    <div class="metric-value">{cal['expected_calibration_error']:.4f}</div>
                </div>
            </div>
        """, unsafe_allow_html=True)
        
        st.markdown("""
            <div style="border-top: 1px dashed #00AA44; border-bottom: 1px dashed #00AA44; padding: 10px 0; margin-top: 20px; margin-bottom: 15px;">
                <span style="font-weight: bold; color: #00FFFF;">[SYS_CALIBRATION::MODEL_RELIABILITY_BINNING]</span>
            </div>
        """, unsafe_allow_html=True)
        
        col_diag1, col_diag2 = st.columns(2)
        with col_diag1:
            st.table(style_reliability_table(cal["reliability_bins"]))
        with col_diag2:
            if HAS_PLOTLY:
                st.plotly_chart(_render_calibration_curve(cal["reliability_bins"]), use_container_width=True)

# --- TAB 4: Feedback Loop ---
with t4:
    st.subheader("FEEDBACK_LOOP_INTEGRATION")
    
    st.markdown("""
        <div style="border-top: 1px dashed #00AA44; border-bottom: 1px dashed #00AA44; padding: 10px 0; margin-top: 20px; margin-bottom: 15px;">
            <span style="font-weight: bold; color: #00FFFF;">[SYS_FEEDBACK::DECISION_INTEGRATION_CONSOLE]</span>
        </div>
    """, unsafe_allow_html=True)
    
    store = FeedbackStore(FEEDBACK_PATH)
    fb_summary = store.summary()
    
    col_fb1, col_fb2 = st.columns(2)
    with col_fb1:
        st.markdown("FEEDBACK_STATISTICS_LOG")
        st.markdown(f"""
            <div class="terminal-block">
                <span style="color: #64748B;">[SYS_FEEDBACK::STATISTICS_LOG]</span><br/>
                &gt;&gt;&gt; TOTAL_REVIEWS_LOGGED: {fb_summary.get('total_feedback', 0)}<br/>
                &gt;&gt;&gt; UNIQUE_FINDINGS_REVIEWED: {len(fb_summary.get('by_finding', {}))}<br/>
                &gt;&gt;&gt; LOG_FILE_PATH: {FEEDBACK_PATH}
            </div>
        """, unsafe_allow_html=True)
        
        decisions = fb_summary.get("by_decision", {})
        if decisions and HAS_PLOTLY:
            dec_series = pd.Series(decisions)
            st.plotly_chart(_render_plotly_bar(dec_series, "HUMAN_DECISIONS_DISTRIBUTION", "#06B6D4"), use_container_width=True)
        
    with col_fb2:
        st.markdown("SUBMIT_CORRECTIVE_ACTION")
        with st.form("feedback_form", clear_on_submit=True):
            fb_finding_id = st.selectbox("Select finding_id to edit", df["finding_id"].tolist())
            fb_decision = st.selectbox("Triage Decision Validation", ["approved", "rejected", "needs_changes", "false_positive", "true_positive"])
            fb_reviewer = st.text_input("Reviewer Name/Signature", value="secops_lead")
            fb_corrected_cwe = st.text_input("Corrected CWE (e.g. CWE-89)", value="")
            fb_notes = st.text_area("Reviewer Notes & Mitigations", value="")
            
            fb_submitted = st.form_submit_button("Record Review Decision")
            if fb_submitted:
                feedback_obj = TriageFeedback(
                    finding_id=fb_finding_id,
                    decision=fb_decision,
                    reviewer=fb_reviewer,
                    notes=fb_notes,
                    corrected_cwe=fb_corrected_cwe if fb_corrected_cwe else None
                )
                store.add(feedback_obj)
                st.success(f"Feedback saved to `{FEEDBACK_PATH}`")

# Global Hacking Footer
st.markdown("""
    <div style="border-top: 1px dashed #00AA44; margin-top: 60px; padding-top: 20px; padding-bottom: 10px; text-align: center; font-family: 'Share Tech Mono', monospace; font-size: 11px; color: #00AA44; letter-spacing: 0.15em;">
        &lt;SYSTEM_FOOTER // SECURITY_TRIAGE_TERMINAL_V5.0 // DEVELOPED_BY: <span style="color: #00FF66; font-weight: bold; text-shadow: 0 0 5px rgba(0, 255, 102, 0.5);">MUNTASIR</span> // SYSTEM_GATE: ENGAGED&gt;
    </div>
""", unsafe_allow_html=True)
