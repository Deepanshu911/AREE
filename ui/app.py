# -*- coding: utf-8 -*-
"""
AREE Dashboard v2.0 — Autonomous Risk Evolution Engine
======================================================
Real-time system monitoring dashboard with live backend integration.

Entry point: streamlit run ui/app.py  (run from project root)
"""
import sys
import os
import time
import datetime
import logging

import streamlit as st
import pandas as pd
import numpy as np

try:
    import plotly.graph_objects as go
    _plotly_available = True
except ImportError:
    _plotly_available = False

# ── Path setup ────────────────────────────────────────────────────────────────
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

logger = logging.getLogger(__name__)

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AREE — Autonomous Risk Evolution Engine",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── CSS Theme ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    body, .stApp { background-color: #020617; color: #FAFAFA; }
    .stApp {
        background: linear-gradient(-45deg,#020617,#0a1120,#071426,#020617);
        background-size: 300% 300%;
        animation: cyberMove 10s ease infinite;
    }
    @keyframes cyberMove {
        0%   { background-position: 0% 50%; }
        50%  { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }
    .dashboard-card {
        background: #0f172a; border: 1px solid #1e293b;
        border-radius: 12px; padding: 20px; margin-bottom: 16px;
    }
    .kpi-card {
        background: #0f172a; border: 1px solid #1e293b; border-radius: 10px;
        padding: 16px; text-align: center;
    }
    .kpi-value { font-size: 32px; font-weight: bold; margin: 4px 0; }
    .kpi-label { font-size: 12px; color: #9CA3AF; }
    .incident-card {
        background: #0f172a; border-left: 4px solid #ef4444;
        border-radius: 8px; padding: 12px 16px; margin-bottom: 8px;
    }
    .incident-card.warning { border-left-color: #f97316; }
    .incident-card.low { border-left-color: #22c55e; }
    .status-live { color: #22c55e; font-weight: bold; }
    .status-stale { color: #f97316; font-weight: bold; }
    .status-unavailable { color: #ef4444; font-weight: bold; }
    .status-simulated { color: #9CA3AF; font-weight: bold; }
    .alert-critical {
        background: linear-gradient(90deg,#3b0d0d,#4a1010,#3b0d0d);
        border: 1px solid #7f1d1d; border-radius: 10px;
        padding: 14px 18px; color: #fecaca; font-weight: 500;
        animation: alertGlow 2s infinite alternate;
    }
    @keyframes alertGlow {
        from { box-shadow: 0 0 5px rgba(239,68,68,0.4); }
        to   { box-shadow: 0 0 18px rgba(239,68,68,0.9); }
    }
    .stMetric label { font-size: 12px !important; }
</style>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# BACKEND INTEGRATION — graceful fallback
# ═══════════════════════════════════════════════════════════════════════════════

_backend_available = False
_agent_module = None
_risk_module = None
_db_module = None

try:
    from agent.collector import MetricCollector, SystemSnapshot
    from agent.detector import DetectionEngine, Incident, Severity
    from agent.watcher import MonitoringAgent
    from engine.risk import compute_oss, compute_re, classify_risk
    from store.db import IncidentDB
    from config.config import load_config
    _backend_available = True
except ImportError as e:
    logger.warning("Real backend not available, using fallback: %s", e)

# Legacy / mock imports
try:
    from core.mock_data import (generate_service_metrics, generate_threat_ips,
                                 generate_incident_log, compute_re_scores,
                                 get_intervention_suggestions)
    _mock_data_available = True
except ImportError:
    _mock_data_available = False

try:
    from core.real_metrics import get_real_metrics, compute_re_from_real
    _real_metrics_available = True
except ImportError:
    _real_metrics_available = False

try:
    from core.auto_remediate import auto_remediate, get_remediation_log, get_system_status
    _auto_remediate_available = True
except ImportError:
    _auto_remediate_available = False

try:
    from visuals.graph_view import build_dependency_graph
    from visuals.timeline import build_timeline_chart
    from visuals.heatmap import build_aura_heatmap
    _visuals_available = True
except ImportError:
    _visuals_available = False

try:
    from utils.pdf_export import generate_pdf
    _pdf_available = True
except ImportError:
    _pdf_available = False

# ═══════════════════════════════════════════════════════════════════════════════
# SESSION STATE INIT
# ═══════════════════════════════════════════════════════════════════════════════

_ss_defaults = {
    "agent": None,
    "db": None,
    "incidents": [],
    "last_snapshot": None,
    "remediation_log": [],
    "pending_approvals": [],
}
for k, v in _ss_defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

# Auto-start agent on initial load if backend available
if st.session_state.get("agent") is None and _backend_available:
    try:
        cfg = load_config() if callable(load_config) else {}
        db = IncidentDB()
        agent = MonitoringAgent(config=cfg, db=db)
        agent.start()
        st.session_state.agent = agent
        st.session_state.db = db
    except Exception as e:
        logger.warning("Agent auto-init error: %s", e)

# ═══════════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ═══════════════════════════════════════════════════════════════════════════════

with st.sidebar:
    st.markdown("### ⚡ AREE v2.0")
    st.markdown("*Autonomous Risk Evolution Engine*")
    st.markdown("---")

    # Data source
    if _backend_available:
        data_mode = st.radio(
            "📡 Data Source",
            ["🟢 Live System Monitoring", "⚪ Mock / Simulation"],
            index=0,
        )
        use_live = "Live" in data_mode
    else:
        st.warning("⚠️ Real backend modules not found. Using mock data.")
        use_live = False
        data_mode = "⚪ Mock / Simulation"

    # Permission / remediation mode
    permission_mode = st.selectbox(
        "🔐 Remediation Mode",
        [
            "OBSERVE (monitor only)",
            "SUGGEST (recommend only)",
            "APPROVED AUTO-FIX (safe actions)",
            "MANUAL (require approval)",
        ],
        index=1,
        help="Controls whether AREE can automatically fix problems.",
    )
    perm_key = permission_mode.split(" ")[0]

    st.markdown("---")

    # Scenario (mock mode only)
    if not use_live:
        scenario = st.selectbox(
            "🎭 Scenario",
            ["Normal Operations", "DDoS Attack", "Config Drift",
             "Brute Force", "Data Exfiltration"],
        )
    else:
        scenario = "Normal Operations"

    n_services = st.slider("🔢 Services to Monitor", 2, 8, 8)

    st.markdown("---")

    st.markdown("**⚠️ Alert Thresholds**")
    warning_threshold  = st.slider("Warning RE %",  20, 70, 45)
    critical_threshold = st.slider("Critical RE %", 50, 95, 75)

    st.markdown("---")
    auto_refresh = st.checkbox("🔄 Auto Refresh (10s)", value=False)

    # Agent controls (live mode only)
    if _backend_available and use_live:
        st.markdown("---")
        st.markdown("**🤖 Monitoring Agent**")
        col_a, col_b = st.columns(2)
        with col_a:
            if st.button("▶ Start", use_container_width=True):
                if st.session_state.agent is None:
                    try:
                        cfg = load_config() if callable(load_config) else {}
                        db  = IncidentDB()
                        agent = MonitoringAgent(config=cfg, db=db)
                        agent.start()
                        st.session_state.agent = agent
                        st.session_state.db    = db
                        st.success("Agent started!")
                    except Exception as e:
                        st.error(f"Start failed: {e}")
                else:
                    st.info("Already running.")
        with col_b:
            if st.button("⏹ Stop", use_container_width=True):
                if st.session_state.agent is not None:
                    st.session_state.agent.stop()
                    st.session_state.agent = None
                    st.success("Agent stopped.")

    st.markdown("---")
    st.caption(f"Mode: **{perm_key}** | {'Live' if use_live else 'Mock'}")

# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

SERVICES = [
    "auth-service", "payment-gateway", "user-db", "api-gateway",
    "notification-svc", "order-service", "inventory-db", "logging-svc",
]

# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def get_data_source_label(use_live: bool, agent_ok: bool,
                           last_time: datetime.datetime = None) -> tuple:
    """Returns (label_html, data_state) for the status banner."""
    if not use_live:
        return '<span class="status-simulated">⚪ SIMULATED</span>', "simulated"
    if not agent_ok:
        return '<span class="status-unavailable">🔴 UNAVAILABLE</span>', "unavailable"
    if last_time is None:
        return '<span class="status-unavailable">🔴 NO DATA YET</span>', "unavailable"
    age_s = (datetime.datetime.utcnow() - last_time).total_seconds()
    if age_s < 30:
        return f'<span class="status-live">🟢 LIVE ({age_s:.0f}s ago)</span>', "live"
    if age_s < 300:
        return f'<span class="status-stale">🟡 STALE ({age_s:.0f}s ago)</span>', "stale"
    return '<span class="status-unavailable">🔴 STALE (&gt;5min)</span>', "unavailable"


def collect_live_data(agent, n_services: int) -> tuple:
    """Collect live data from a running agent. Returns (df, incidents, snapshot, error)."""
    try:
        snapshot  = agent.get_latest_snapshot()
        incidents = agent.get_recent_incidents(limit=20)
        if snapshot is None:
            return None, [], None, "No snapshot available yet"
        if _real_metrics_available:
            metrics_df = get_real_metrics(n_services)
            # Try canonical RE formula first
            try:
                from engine.risk import compute_oss, compute_re  # noqa: F811
                re_scores = []
                for _, row in metrics_df.iterrows():
                    oss = compute_oss(cpu_pct=row["cpu"], ram_pct=row["memory"],
                                      latency_ms=row["latency_ms"])
                    re  = compute_re(oss=oss, tes=0.0, dss=0.0, bcs=0.5)
                    re_scores.append(re)
                metrics_df["re_score"] = re_scores
            except ImportError:
                metrics_df = compute_re_from_real(metrics_df)
        else:
            return None, [], None, "real_metrics module unavailable"
        return metrics_df, incidents, snapshot, None
    except Exception as e:
        return None, [], None, str(e)


def collect_mock_data(scenario: str, n_services: int,
                      warning_thr: float, critical_thr: float) -> tuple:
    """Generate scenario-based mock data. Returns (df, [], None, error)."""
    import random
    rows = []
    for svc in SERVICES[:n_services]:
        if scenario == "DDoS Attack":
            cpu = random.uniform(70, 95)
            tes = random.uniform(0.7, 0.95)
        elif scenario == "Config Drift":
            cpu = random.uniform(40, 70)
            tes = random.uniform(0.3, 0.6)
        elif scenario == "Brute Force":
            cpu = random.uniform(30, 60)
            tes = random.uniform(0.7, 0.9)
        elif scenario == "Data Exfiltration":
            cpu = random.uniform(20, 45)
            tes = random.uniform(0.8, 0.99)
        else:  # Normal
            cpu = random.uniform(10, 50)
            tes = random.uniform(0.0, 0.25)

        mem       = random.uniform(20, 80)
        latency   = 50 + (cpu / 100) * 750 + random.uniform(-20, 20)
        err_rate  = max(0, (cpu - 60) / 40 * 25) if cpu > 60 else random.uniform(0, 3)

        try:
            from engine.risk import compute_oss, compute_re  # noqa: F811
            oss = compute_oss(cpu_pct=cpu, ram_pct=mem, latency_ms=latency)
            re  = compute_re(oss=oss, tes=tes, dss=0.0, bcs=0.5)
        except ImportError:
            # Legacy fallback formula
            re = (cpu / 100 * 40) + (err_rate / 25 * 30) + (latency / 800 * 20) + (tes * 10)
            re = min(re, 100.0)

        rows.append({
            "service":     svc,
            "cpu":         round(cpu, 2),
            "memory":      round(mem, 2),
            "error_rate":  round(err_rate, 2),
            "latency_ms":  round(latency, 2),
            "req_per_sec": random.randint(50, 1000),
            "re_score":    round(re, 2),
        })

    df = pd.DataFrame(rows)
    return df, [], None, None


# ═══════════════════════════════════════════════════════════════════════════════
# DATA COLLECTION
# ═══════════════════════════════════════════════════════════════════════════════

agent         = st.session_state.agent
agent_running = (
    agent is not None
    and hasattr(agent, "is_running")
    and agent.is_running
)

if use_live and agent_running:
    data, incidents, snapshot, data_err = collect_live_data(agent, n_services)
    last_time = snapshot.timestamp if snapshot else None
    if data is None or (hasattr(data, "empty") and data.empty):
        if _real_metrics_available:
            try:
                data = compute_re_from_real(get_real_metrics(n_services))
                data_err = None
            except Exception as fe:
                data_err = str(fe)
elif use_live:
    # Live requested but no agent — use psutil directly via real_metrics
    try:
        data      = compute_re_from_real(get_real_metrics(n_services))
        incidents = []
        snapshot  = None
        last_time = datetime.datetime.utcnow()
        data_err  = None
    except Exception as e:
        data, incidents, snapshot, last_time, data_err = (
            pd.DataFrame(), [], None, None, str(e))
else:
    data, incidents, snapshot, data_err = collect_mock_data(
        scenario, n_services, warning_threshold, critical_threshold)
    last_time = datetime.datetime.utcnow()

# Abort on total data failure
if data is None or (hasattr(data, "empty") and data.empty):
    st.error(f"❌ Data collection failed: {data_err or 'Unknown error'}")
    st.info("Try switching to **Mock / Simulation** mode in the sidebar.")
    st.stop()

# Apply auto-remediation simulation (SUGGEST / APPROVED modes)
rem_actions = []
if _auto_remediate_available and "re_score" in data.columns:
    if perm_key in ("SUGGEST", "APPROVED", "MANUAL"):
        try:
            data, rem_actions = auto_remediate(data, critical_threshold=critical_threshold)
            if rem_actions:
                st.session_state.remediation_log.extend(rem_actions)
        except Exception:
            rem_actions = []

# ═══════════════════════════════════════════════════════════════════════════════
# HEADER + STATUS BANNER
# ═══════════════════════════════════════════════════════════════════════════════

st.markdown("# ⚡ AREE — Autonomous Risk Evolution Engine")
st.markdown("*Real-Time System Risk Monitoring & Self-Healing Platform*")

label_html, data_state = get_data_source_label(
    use_live=use_live,
    agent_ok=agent_running,
    last_time=last_time if use_live else None,
)
mode_note = f"Mode: **{perm_key}**"
st.markdown(
    f'<div class="dashboard-card" style="padding:10px 16px;">'
    f'Data Source: {label_html} &nbsp;|&nbsp; {mode_note} &nbsp;|&nbsp; '
    f'Updated: {datetime.datetime.now().strftime("%H:%M:%S")}'
    f'</div>',
    unsafe_allow_html=True,
)

# ═══════════════════════════════════════════════════════════════════════════════
# KPI CARDS
# ═══════════════════════════════════════════════════════════════════════════════

avg_re         = data["re_score"].mean()         if "re_score" in data.columns else 0.0
critical_count = int((data["re_score"] >= critical_threshold).sum()) if "re_score" in data.columns else 0
warning_count  = int(((data["re_score"] >= warning_threshold) &
                       (data["re_score"] < critical_threshold)).sum()) if "re_score" in data.columns else 0
health_score   = max(0.0, 100.0 - avg_re)

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    hc = "#22c55e" if health_score >= 70 else "#f97316" if health_score >= 40 else "#ef4444"
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-label">System Health</div>
        <div class="kpi-value" style="color:{hc}">{health_score:.1f}%</div>
    </div>""", unsafe_allow_html=True)

with col2:
    rc = "#ef4444" if avg_re >= critical_threshold else "#f97316" if avg_re >= warning_threshold else "#22c55e"
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-label">Avg Risk Energy</div>
        <div class="kpi-value" style="color:{rc}">{avg_re:.1f}</div>
    </div>""", unsafe_allow_html=True)

with col3:
    cc = "#ef4444" if critical_count > 0 else "#22c55e"
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-label">Critical Services</div>
        <div class="kpi-value" style="color:{cc}">{critical_count}</div>
    </div>""", unsafe_allow_html=True)

with col4:
    wc = "#f97316" if warning_count > 0 else "#22c55e"
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-label">Warning Services</div>
        <div class="kpi-value" style="color:{wc}">{warning_count}</div>
    </div>""", unsafe_allow_html=True)

with col5:
    ac = "#22c55e" if agent_running else "#9CA3AF"
    at = "ACTIVE" if agent_running else "INACTIVE"
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-label">Agent Status</div>
        <div class="kpi-value" style="color:{ac};font-size:20px">{at}</div>
    </div>""", unsafe_allow_html=True)

st.markdown("---")

# ═══════════════════════════════════════════════════════════════════════════════
# AGENT STATUS PANEL
# ═══════════════════════════════════════════════════════════════════════════════

with st.expander("🤖 Agent Status", expanded=False):
    a_col1, a_col2, a_col3 = st.columns(3)
    with a_col1:
        st.markdown(
            f'<div class="kpi-card"><div class="kpi-label">Backend Modules</div>'
            f'<div class="kpi-value" style="color:{"#22c55e" if _backend_available else "#ef4444"};font-size:16px;">'
            f'{"AVAILABLE" if _backend_available else "NOT FOUND"}</div></div>',
            unsafe_allow_html=True)
    with a_col2:
        st.markdown(
            f'<div class="kpi-card"><div class="kpi-label">Real Metrics</div>'
            f'<div class="kpi-value" style="color:{"#22c55e" if _real_metrics_available else "#ef4444"};font-size:16px;">'
            f'{"AVAILABLE" if _real_metrics_available else "NOT FOUND"}</div></div>',
            unsafe_allow_html=True)
    with a_col3:
        st.markdown(
            f'<div class="kpi-card"><div class="kpi-label">Visuals</div>'
            f'<div class="kpi-value" style="color:{"#22c55e" if _visuals_available else "#ef4444"};font-size:16px;">'
            f'{"AVAILABLE" if _visuals_available else "NOT FOUND"}</div></div>',
            unsafe_allow_html=True)

    if agent_running and hasattr(agent, "get_status"):
        try:
            status_info = agent.get_status()
            st.json(status_info)
        except Exception:
            pass

    last_update_str = last_time.strftime("%H:%M:%S UTC") if last_time else "N/A"
    st.markdown(f"**Last data collection:** `{last_update_str}` &nbsp;|&nbsp; "
                f"**Data mode:** `{data_state.upper()}`")

# ═══════════════════════════════════════════════════════════════════════════════
# REAL SYSTEM METRICS (live mode)
# ═══════════════════════════════════════════════════════════════════════════════

if use_live:
    with st.expander("🖥️ Real System Metrics (Live)", expanded=True):
        if snapshot is not None:
            c1, c2, c3 = st.columns(3)
            cpu_pct = getattr(snapshot, "cpu_percent", None)
            ram_pct = getattr(snapshot, "ram_percent", None)
            uptime  = getattr(snapshot, "uptime_seconds", None)
            ram_avail = getattr(snapshot, "ram_available_gb", None)
            with c1:
                if cpu_pct is not None:
                    cpu_c = "#ef4444" if cpu_pct > 85 else "#f97316" if cpu_pct > 70 else "#22c55e"
                    st.markdown(
                        f'<div class="kpi-card"><div class="kpi-label">CPU</div>'
                        f'<div class="kpi-value" style="color:{cpu_c}">{cpu_pct:.1f}%</div></div>',
                        unsafe_allow_html=True)
            with c2:
                if ram_pct is not None:
                    ram_c = "#ef4444" if ram_pct > 90 else "#f97316" if ram_pct > 75 else "#22c55e"
                    extra = f"{ram_avail:.1f} GB free" if ram_avail else ""
                    st.markdown(
                        f'<div class="kpi-card"><div class="kpi-label">RAM</div>'
                        f'<div class="kpi-value" style="color:{ram_c}">{ram_pct:.1f}%</div>'
                        f'<div class="kpi-label">{extra}</div></div>',
                        unsafe_allow_html=True)
            with c3:
                if uptime is not None:
                    uptime_h = uptime / 3600
                    st.markdown(
                        f'<div class="kpi-card"><div class="kpi-label">Uptime</div>'
                        f'<div class="kpi-value" style="color:#22c55e;font-size:20px">{uptime_h:.1f}h</div></div>',
                        unsafe_allow_html=True)

            disk_parts = getattr(snapshot, "disk_partitions", [])
            if disk_parts:
                st.markdown("**Disk Partitions**")
                for part in disk_parts:
                    pct   = getattr(part, "percent_used", 0)
                    free  = getattr(part, "free_gb", 0)
                    mnt   = getattr(part, "mountpoint", "?")
                    d_c   = "#ef4444" if pct > 90 else "#f97316" if pct > 75 else "#22c55e"
                    st.markdown(
                        f'<div style="margin-bottom:8px;">'
                        f'<div style="display:flex;justify-content:space-between;color:#9CA3AF;font-size:12px;">'
                        f'<span>💾 {mnt}</span>'
                        f'<span style="color:{d_c};">{pct:.1f}% — {free:.1f}GB free</span></div>'
                        f'<div style="background:#1f2937;border-radius:4px;height:8px;margin-top:4px;">'
                        f'<div style="width:{min(pct,100)}%;background:{d_c};height:100%;border-radius:4px;"></div>'
                        f'</div></div>', unsafe_allow_html=True)
        else:
            # No agent snapshot — use psutil directly
            try:
                import psutil
                cpu_pct = psutil.cpu_percent(interval=0.5)
                ram     = psutil.virtual_memory()
                cpu_c   = "#ef4444" if cpu_pct > 85 else "#f97316" if cpu_pct > 70 else "#22c55e"
                ram_c   = "#ef4444" if ram.percent > 90 else "#f97316" if ram.percent > 75 else "#22c55e"
                c1, c2  = st.columns(2)
                with c1:
                    st.markdown(
                        f'<div class="kpi-card"><div class="kpi-label">CPU (Host)</div>'
                        f'<div class="kpi-value" style="color:{cpu_c}">{cpu_pct:.1f}%</div></div>',
                        unsafe_allow_html=True)
                with c2:
                    st.markdown(
                        f'<div class="kpi-card"><div class="kpi-label">RAM (Host)</div>'
                        f'<div class="kpi-value" style="color:{ram_c}">{ram.percent:.1f}%</div>'
                        f'<div class="kpi-label">{ram.available/1024**3:.1f} GB free</div></div>',
                        unsafe_allow_html=True)
            except Exception as e:
                st.warning(f"psutil unavailable: {e}")

# ═══════════════════════════════════════════════════════════════════════════════
# ACTIVE INCIDENTS PANEL
# ═══════════════════════════════════════════════════════════════════════════════

st.markdown("---")
st.markdown("### 🚨 Active Incidents")

all_incidents = list(incidents) if incidents else []

# Supplement with threshold-based incidents derived from service data
for _, row in data.iterrows():
    re = row.get("re_score", 0)
    if re >= critical_threshold:
        all_incidents.append({
            "severity":           "CRITICAL",
            "resource":           row["service"],
            "explanation":        f"{row['service']} RE={re:.1f} exceeds critical threshold ({critical_threshold}).",
            "probable_cause":     f"CPU: {row.get('cpu',0):.1f}%, Error Rate: {row.get('error_rate',0):.1f}%",
            "recommended_action": f"Isolate {row['service']} and inspect dependent services.",
            "incident_id":        f"dash-{row['service'][:4]}-{int(re)}",
        })

if not all_incidents:
    st.success("✅ No active incidents — all services within normal parameters.")
else:
    for inc in all_incidents[:10]:
        sev              = inc.get("severity", "MEDIUM")      if isinstance(inc, dict) else getattr(inc, "severity", "MEDIUM")
        resource         = inc.get("resource", "unknown")     if isinstance(inc, dict) else getattr(inc, "resource", "unknown")
        explanation      = inc.get("explanation", "")         if isinstance(inc, dict) else getattr(inc, "explanation", "")
        probable_cause   = inc.get("probable_cause", "")      if isinstance(inc, dict) else getattr(inc, "probable_cause", "")
        recommended_act  = inc.get("recommended_action", "")  if isinstance(inc, dict) else getattr(inc, "recommended_action", "")
        inc_id           = inc.get("incident_id", "N/A")      if isinstance(inc, dict) else getattr(inc, "incident_id", "N/A")

        sev_class = "" if sev == "CRITICAL" else " warning" if sev in ("MEDIUM", "HIGH") else " low"
        st.markdown(f"""
        <div class="incident-card{sev_class}">
            <div style="display:flex;justify-content:space-between;margin-bottom:6px;">
                <span style="font-weight:bold;color:white;">{resource}</span>
                <span style="font-size:11px;background:#1f2937;padding:2px 8px;border-radius:4px;">{sev}</span>
            </div>
            <div style="color:#d1d5db;font-size:13px;margin-bottom:4px;">📋 {explanation}</div>
            <div style="color:#9CA3AF;font-size:12px;">🔍 {probable_cause}</div>
            <div style="color:#60a5fa;font-size:12px;margin-top:4px;">💡 {recommended_act}</div>
            <div style="color:#4b5563;font-size:10px;margin-top:6px;">ID: {inc_id}</div>
        </div>""", unsafe_allow_html=True)

        # Approval button in MANUAL mode
        if perm_key == "MANUAL" and sev == "CRITICAL":
            if st.button(f"✅ Approve Fix for {resource}", key=f"approve-{inc_id}"):
                st.session_state.pending_approvals.append(inc_id)
                st.success(f"Action queued for {resource}")

# ═══════════════════════════════════════════════════════════════════════════════
# HEALTH GAUGE + SERVICE OVERVIEW
# ═══════════════════════════════════════════════════════════════════════════════

st.markdown("---")
col_gauge, col_table = st.columns([1, 1])

with col_gauge:
    st.markdown("### 🩺 System Health Score")
    if _plotly_available:
        gauge_fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=health_score,
            title={"text": "System Stability Index"},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": "#00C896"},
                "steps": [
                    {"range": [0, 40],   "color": "#4a1010"},
                    {"range": [40, 70],  "color": "#3a2a00"},
                    {"range": [70, 100], "color": "#0a2a1a"},
                ],
                "threshold": {
                    "line": {"color": "#ef4444", "width": 4},
                    "thickness": 0.75,
                    "value": 100 - critical_threshold,
                },
            },
        ))
        gauge_fig.update_layout(paper_bgcolor="#020617", font={"color": "white"}, height=300)
        st.plotly_chart(gauge_fig, use_container_width=True)
    else:
        st.metric("System Stability Index", f"{health_score:.1f}%")
        st.progress(max(0.0, min(1.0, health_score / 100.0)))

with col_table:
    st.markdown("### 📊 Service Risk Overview")
    if "re_score" in data.columns:
        risk_table = data[["service", "re_score"]].sort_values("re_score", ascending=False)
        for _, row in risk_table.iterrows():
            score = row["re_score"]
            color = "#ef4444" if score >= critical_threshold else "#f97316" if score >= warning_threshold else "#22c55e"
            st.markdown(
                f'<div style="display:flex;align-items:center;margin-bottom:10px;">'
                f'<div style="width:160px;color:#cbd5f5;">{row["service"]}</div>'
                f'<div style="flex:1;height:10px;background:#1f2937;border-radius:5px;margin:0 10px;">'
                f'<div style="width:{score}%;height:100%;background:{color};border-radius:5px;"></div></div>'
                f'<div style="width:60px;text-align:right;color:{color};">{score:.1f}</div>'
                f'</div>', unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# AURA HEATMAP
# ═══════════════════════════════════════════════════════════════════════════════

if _visuals_available:
    st.markdown("---")
    st.markdown("### 🌡️ Risk Aura Heatmap")
    try:
        heatmap_fig = build_aura_heatmap(
            data,
            critical_threshold=critical_threshold,
            warning_threshold=warning_threshold,
        )
        st.pyplot(heatmap_fig)
    except Exception as e:
        st.warning(f"Heatmap unavailable: {e}")

# ═══════════════════════════════════════════════════════════════════════════════
# RISK TIMELINE
# ═══════════════════════════════════════════════════════════════════════════════

if _visuals_available:
    st.markdown("---")
    st.markdown("### 📈 Risk Energy Timeline")
    try:
        timeline_fig = build_timeline_chart(
            data,
            scenario=scenario,
            critical_threshold=critical_threshold,
            warning_threshold=warning_threshold,
        )
        st.plotly_chart(timeline_fig, use_container_width=True)
    except Exception as e:
        st.warning(f"Timeline unavailable: {e}")

# ═══════════════════════════════════════════════════════════════════════════════
# DEPENDENCY GRAPH
# ═══════════════════════════════════════════════════════════════════════════════

if _visuals_available:
    st.markdown("---")
    st.markdown("### 🔗 Service Dependency & Risk Cascade Graph")
    try:
        graph_fig = build_dependency_graph(
            data,
            critical_threshold=critical_threshold,
            warning_threshold=warning_threshold,
        )
        st.plotly_chart(graph_fig, use_container_width=True)
    except Exception as e:
        st.warning(f"Graph unavailable: {e}")

# ═══════════════════════════════════════════════════════════════════════════════
# REMEDIATION LOG
# ═══════════════════════════════════════════════════════════════════════════════

st.markdown("---")
st.markdown("### 🔧 Remediation Log")

rem_log = list(st.session_state.remediation_log)
if _auto_remediate_available:
    try:
        mock_log = get_remediation_log()
        if hasattr(mock_log, "iterrows"):
            for _, mrow in mock_log.iterrows():
                rem_log.append(dict(mrow))
    except Exception:
        pass

if not rem_log:
    st.success("✅ No interventions triggered this session — system stable.")
else:
    for entry in rem_log[-20:]:
        if isinstance(entry, dict):
            sev   = entry.get("severity", "")
            color = "#ef4444" if sev == "CRITICAL" else "#f97316"
            st.markdown(
                f'<div style="background:#0f172a;border-left:4px solid {color};'
                f'padding:10px 16px;border-radius:6px;margin-bottom:8px;">'
                f'<span style="color:#9CA3AF;font-size:12px;">{entry.get("timestamp","")}</span>'
                f'<span style="color:white;font-weight:bold;margin-left:12px;">{entry.get("service","")}</span>'
                f'<span style="color:{color};margin-left:12px;">'
                f'RE: {entry.get("re_before","")} → {entry.get("re_after","")}</span>'
                f'<div style="color:#d1d5db;font-size:13px;margin-top:4px;">{entry.get("action","")}</div>'
                f'</div>', unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# PENDING APPROVALS (MANUAL mode)
# ═══════════════════════════════════════════════════════════════════════════════

if perm_key == "MANUAL" and st.session_state.pending_approvals:
    st.markdown("---")
    st.markdown("### ✋ Pending Approvals")
    for appr_id in st.session_state.pending_approvals:
        st.markdown(
            f'<div style="background:#0f172a;border-left:4px solid #f97316;'
            f'padding:10px 16px;border-radius:6px;margin-bottom:8px;">'
            f'<span style="color:#f97316;">⏳ Queued:</span>'
            f'<span style="color:white;margin-left:8px;">{appr_id}</span>'
            f'</div>', unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# EXPORT + REFRESH
# ═══════════════════════════════════════════════════════════════════════════════

st.markdown("---")
col_dl, col_refresh = st.columns(2)

with col_dl:
    if _pdf_available:
        if st.button("📄 Export PDF Report", use_container_width=True):
            try:
                inc_df   = pd.DataFrame(all_incidents) if all_incidents else pd.DataFrame(
                    columns=["incident_id", "severity", "resource", "explanation"])
                pdf_bytes = generate_pdf(data, inc_df)
                st.download_button(
                    label="⬇ Download Report",
                    data=pdf_bytes.read() if hasattr(pdf_bytes, "read") else pdf_bytes,
                    file_name=f"aree_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                )
            except Exception as e:
                st.error(f"PDF export failed: {e}")
    else:
        st.info("PDF export: install `reportlab`")

with col_refresh:
    if st.button("🔄 Refresh Now", use_container_width=True):
        st.rerun()

# ═══════════════════════════════════════════════════════════════════════════════
# AUTO REFRESH
# ═══════════════════════════════════════════════════════════════════════════════

if auto_refresh:
    time.sleep(10)
    st.rerun()

# ═══════════════════════════════════════════════════════════════════════════════
# FOOTER
# ═══════════════════════════════════════════════════════════════════════════════

st.markdown("---")
st.markdown(
    f'<div style="text-align:center;color:#4b5563;font-size:11px;">'
    f'AREE v2.0 — Autonomous Risk Evolution Engine | TeamIntelloQ | '
    f'Data: {data_state.upper()} | '
    f'{datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'
    f'</div>',
    unsafe_allow_html=True,
)
