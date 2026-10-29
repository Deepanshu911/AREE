# -*- coding: utf-8 -*-
"""
AREE Dashboard v2.1 — Autonomous Risk Evolution Engine
======================================================
Multi-Device Real-Time System Monitoring & Safe Self-Healing Platform.

Supports:
  - Mode A: Zero-install Browser-Reported Capabilities Sandbox
  - Mode B: Full Local Device Monitoring via Enrolled AREE Agents
  - Cloud Host Monitoring: Transparent container performance telemetry
"""
import datetime
import json
import logging
import os
import sys
import time

import numpy as np
import pandas as pd
import streamlit as st

try:
    import plotly.graph_objects as go
    _plotly_available = True
except ImportError:
    _plotly_available = False

# ── Path setup ────────────────────────────────────────────────────────────────
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
if os.path.dirname(os.path.abspath(__file__)) not in sys.path:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

logger = logging.getLogger(__name__)

# ── Monitored Microservice Topology ──────────────────────────────────────────
SERVICES = ["auth-service", "api-gateway", "payment-gateway", "user-db", "order-service", "cache-redis"]

# ── Ensure API routes are mounted on Streamlit's Tornado server ───────────────
try:
    from server.tornado_mount import ensure_api_mounted
    ensure_api_mounted()
except Exception as e:
    logger.debug("API mount check: %s", e)

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AREE — Multi-Device Cyber Risk & Monitoring",
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
        animation: cyberMove 12s ease infinite;
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
    .kpi-value { font-size: 30px; font-weight: bold; margin: 4px 0; }
    .kpi-label { font-size: 11px; color: #9CA3AF; text-transform: uppercase; letter-spacing: 0.5px; }
    .incident-card {
        background: #0f172a; border-left: 4px solid #ef4444;
        border-radius: 8px; padding: 12px 16px; margin-bottom: 8px;
    }
    .incident-card.warning { border-left-color: #f97316; }
    .incident-card.low { border-left-color: #22c55e; }
    .status-badge {
        display: inline-block; padding: 3px 10px; border-radius: 12px;
        font-size: 11px; font-weight: 600; text-transform: uppercase;
    }
    .badge-connected { background: #064e3b; color: #34d399; border: 1px solid #059669; }
    .badge-stale { background: #78350f; color: #fbbf24; border: 1px solid #d97706; }
    .badge-disconnected { background: #7f1d1d; color: #f87171; border: 1px solid #dc2626; }
    .badge-browser { background: #1e3a8a; color: #60a5fa; border: 1px solid #2563eb; }
    .badge-cloud { background: #4c1d95; color: #c084fc; border: 1px solid #7c3aed; }
</style>
""", unsafe_allow_html=True)

# ── Backend Integration ───────────────────────────────────────────────────────
_backend_available = False
try:
    from agent.collector import MetricCollector, SystemSnapshot
    from agent.detector import DetectionEngine, Incident, Severity
    from agent.watcher import MonitoringAgent
    from engine.risk import compute_oss, compute_re, classify_risk
    from store.db import IncidentDB
    from config.config import load_config
    from server.device_manager import DeviceManager
    _backend_available = True
except ImportError as e:
    logger.warning("Backend load warning: %s", e)

try:
    from core.mock_data import generate_service_metrics, generate_threat_ips
    _mock_data_available = True
except ImportError:
    _mock_data_available = False

try:
    from core.real_metrics import get_real_metrics, compute_re_from_real
    _real_metrics_available = True
except ImportError:
    _real_metrics_available = False

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

# ── State Initialization ──────────────────────────────────────────────────────
db = IncidentDB() if _backend_available else None
device_mgr = DeviceManager(db) if _backend_available else None

if "remediation_log" not in st.session_state:
    st.session_state.remediation_log = []
if "enrollment_info" not in st.session_state:
    st.session_state.enrollment_info = None

# Auto-start local cloud-host agent if running locally
if "cloud_agent" not in st.session_state and _backend_available:
    try:
        cfg = load_config() if callable(load_config) else {}
        cloud_agent = MonitoringAgent(config=cfg, db=db)
        cloud_agent.start()
        st.session_state.cloud_agent = cloud_agent
    except Exception as e:
        logger.debug("Cloud agent auto-init: %s", e)

# ═══════════════════════════════════════════════════════════════════════════════
# SIDEBAR — MULTI-DEVICE SELECTOR & ENROLLMENT
# ═══════════════════════════════════════════════════════════════════════════════

with st.sidebar:
    st.markdown("### ⚡ AREE Multi-Device")
    st.markdown("*Autonomous Risk Evolution Engine v2.1*")
    st.markdown("---")

    # 1. Device Selection Dropdown
    enrolled_devices = db.list_devices() if db else []

    device_options = [
        "🌐 Current Device (Browser-Reported Sandbox)",
        "🖥️ Cloud Server (Streamlit Host Container)",
    ]

    device_map = {}
    for d in enrolled_devices:
        conn_status = d.get("connection_status", "connected").upper()
        icon = "🟢" if conn_status == "CONNECTED" else "🟡" if conn_status == "STALE" else "🔴"
        label = f"💻 {d['device_name']} ({d['device_id']}) [{icon} {conn_status}]"
        device_options.append(label)
        device_map[label] = d

    selected_option = st.selectbox(
        "📱 Monitored Target Device",
        device_options,
        index=0,
        help="Select which physical computer or browser session to monitor."
    )

    is_browser_mode = "Browser-Reported" in selected_option
    is_cloud_mode = "Cloud Server" in selected_option
    is_enrolled_mode = not is_browser_mode and not is_cloud_mode
    active_device_data = device_map.get(selected_option) if is_enrolled_mode else None

    st.markdown("---")

    # 2. Permission Mode
    permission_mode = st.selectbox(
        "🔐 Remediation Policy",
        [
            "SUGGEST (Operator Dispatch Required)",
            "APPROVED_AUTO (Execute Safe Allowlist)",
            "MANUAL (Interactive Approval Tokens)",
            "OBSERVE (Monitor Only)",
        ],
        index=0,
    )
    perm_key = permission_mode.split(" ")[0]

    # 3. Alert Thresholds
    st.markdown("**⚠️ Risk Thresholds**")
    warning_threshold = st.slider("Warning RE %", 20, 70, 45)
    critical_threshold = st.slider("Critical RE %", 50, 95, 75)

    st.markdown("---")
    auto_refresh_sec = st.selectbox("🔄 Auto-Refresh Interval", ["Off", "5 seconds", "10 seconds", "30 seconds"], index=2)

    # 4. Device Enrollment Drawer
    with st.expander("➕ Enroll a New Computer"):
        st.markdown("**Connect your Laptop / PC**")
        new_dev_name = st.text_input("Device Name", value="My-Workstation", key="new_dev_name")
        new_dev_os = st.selectbox("Operating System", ["Windows", "Linux", "macOS"], index=0)

        if st.button("Generate Enrollment Token", use_container_width=True):
            if device_mgr:
                new_id, raw_token = device_mgr.enroll_device(device_name=new_dev_name, os_type=new_dev_os)
                st.session_state.enrollment_info = {
                    "device_id": new_id,
                    "token": raw_token,
                    "name": new_dev_name,
                    "os": new_dev_os,
                }
                st.success(f"Device enrolled! ID: `{new_id}`")

        if st.session_state.enrollment_info:
            e_info = st.session_state.enrollment_info
            st.markdown(f"**Token:** `{e_info['token']}`")
            st.markdown("*Run on your target computer:*")
            cmd = f"python aree_agent.py --server http://localhost:8501 --device-id {e_info['device_id']} --token {e_info['token']}"
            st.code(cmd, language="bash")
            st.caption("Replace localhost with your public Streamlit URL if running in cloud.")

# ═══════════════════════════════════════════════════════════════════════════════
# MODE A — BROWSER-REPORTED STATUS (ZERO-INSTALL)
# ═══════════════════════════════════════════════════════════════════════════════

if is_browser_mode:
    st.markdown("## 🌐 Mode A: Browser-Reported Capabilities Sandbox")
    st.markdown(
        f'<div class="dashboard-card">'
        f'<span class="status-badge badge-browser">Mode A: Browser Sandbox</span> &nbsp;|&nbsp; '
        f'Target: <b>Visitor Web Session</b> &nbsp;|&nbsp; '
        f'Status: <span style="color:#60a5fa;font-weight:bold;">Active Connection</span>'
        f'</div>',
        unsafe_allow_html=True
    )

    st.info(
        "🛡️ **Browser Sandbox Boundary:** You are viewing this device through standard web browser capabilities. "
        "A secure web browser cannot inspect operating system processes, physical CPU hardware load, or local filesystem contents. "
        "To inspect full OS metrics and enable autonomous self-healing, enroll this computer with the **AREE Agent** via the sidebar."
    )

    # Interactive Browser Footprint JavaScript Component
    st.components.v1.html("""
    <div id="browser-telemetry" style="background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:20px;font-family:system-ui,sans-serif;color:#FAFAFA;">
        <div style="font-size:16px;font-weight:bold;margin-bottom:12px;color:#60a5fa;">📊 Browser-Accessible Client Diagnostics</div>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;">
            <div style="background:#1e293b;padding:12px;border-radius:8px;">
                <div style="color:#94a3b8;font-size:11px;">BROWSER PLATFORM</div>
                <div id="b-platform" style="font-size:16px;font-weight:bold;margin-top:4px;">Detecting...</div>
            </div>
            <div style="background:#1e293b;padding:12px;border-radius:8px;">
                <div style="color:#94a3b8;font-size:11px;">LOGICAL CPU CORES</div>
                <div id="b-cores" style="font-size:16px;font-weight:bold;margin-top:4px;">Detecting...</div>
            </div>
            <div style="background:#1e293b;padding:12px;border-radius:8px;">
                <div style="color:#94a3b8;font-size:11px;">APPROX DEVICE MEMORY</div>
                <div id="b-memory" style="font-size:16px;font-weight:bold;margin-top:4px;">Detecting...</div>
            </div>
            <div style="background:#1e293b;padding:12px;border-radius:8px;">
                <div style="color:#94a3b8;font-size:11px;">NETWORK STATUS</div>
                <div id="b-network" style="font-size:16px;font-weight:bold;margin-top:4px;">Detecting...</div>
            </div>
            <div style="background:#1e293b;padding:12px;border-radius:8px;">
                <div style="color:#94a3b8;font-size:11px;">SCREEN VIEWPORT</div>
                <div id="b-screen" style="font-size:16px;font-weight:bold;margin-top:4px;">Detecting...</div>
            </div>
            <div style="background:#1e293b;padding:12px;border-radius:8px;">
                <div style="color:#94a3b8;font-size:11px;">RENDER LATENCY</div>
                <div id="b-latency" style="font-size:16px;font-weight:bold;color:#34d399;margin-top:4px;">Detecting...</div>
            </div>
        </div>
    </div>
    <script>
        const start = performance.now();
        document.getElementById('b-platform').innerText = navigator.platform || navigator.userAgentData?.platform || 'Standard Web';
        document.getElementById('b-cores').innerText = (navigator.hardwareConcurrency || 'N/A') + ' Cores';
        document.getElementById('b-memory').innerText = navigator.deviceMemory ? (navigator.deviceMemory + ' GiB') : 'Restricted by Browser';
        
        const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
        let netInfo = navigator.onLine ? '🟢 Online' : '🔴 Offline';
        if (conn && conn.effectiveType) {
            netInfo += ' (' + conn.effectiveType.toUpperCase() + ', ~' + (conn.downlink || '10') + 'Mbps)';
        }
        document.getElementById('b-network').innerText = netInfo;
        document.getElementById('b-screen').innerText = window.innerWidth + 'x' + window.innerHeight + ' (' + screen.width + 'x' + screen.height + ')';
        
        window.onload = function() {
            const duration = Math.round(performance.now() - start);
            document.getElementById('b-latency').innerText = duration + ' ms';
        };
    </script>
    """, height=220)

    st.markdown("---")
    st.markdown("### 📥 Want Full Local Monitoring for this Computer?")
    c_inst1, c_inst2 = st.columns(2)
    with c_inst1:
        st.markdown("""
        **Step 1: Install prerequisites**
        ```bash
        pip install psutil requests
        ```
        """)
    with c_inst2:
        st.markdown("""
        **Step 2: Run the AREE Agent**
        ```bash
        python aree_agent.py --server https://<your-deployed-url> --enroll --name "My-Device"
        ```
        """)

# ═══════════════════════════════════════════════════════════════════════════════
# MODE B & CLOUD HOST — FULL LOCAL SYSTEM MONITORING
# ═══════════════════════════════════════════════════════════════════════════════

else:
    # Determine target device identity
    if is_cloud_mode:
        active_id = "cloud-host"
        device_display_name = "Cloud Server (Streamlit Host Container)"
        os_display = "Linux / Container"
        badge_html = '<span class="status-badge badge-cloud">Host Container Telemetry</span>'
        # Get live data directly from psutil on cloud host
        if _real_metrics_available:
            data = compute_re_from_real(get_real_metrics(8))
        else:
            data = pd.DataFrame()
        snapshot_dict = db.get_latest_snapshot("cloud-host") if db else None
        active_status = "CONNECTED"
        last_updated = datetime.datetime.utcnow().strftime("%H:%M:%S UTC")
    else:
        # Enrolled device
        active_id = active_device_data["device_id"]
        device_display_name = active_device_data.get("device_name", active_id)
        os_display = active_device_data.get("os_type", "Unknown OS")
        conn_state = active_device_data.get("connection_status", "connected").upper()
        badge_cls = "badge-connected" if conn_state == "CONNECTED" else "badge-stale" if conn_state == "STALE" else "badge-disconnected"
        badge_html = f'<span class="status-badge {badge_cls}">{conn_state}</span>'

        # Fetch latest metrics reported by agent
        snapshot_dict = db.get_latest_snapshot(active_id) if db else None
        active_status = conn_state

        if snapshot_dict:
            last_updated = snapshot_dict.get("timestamp", "N/A")
            # Build DataFrame for visualization
            raw_meta = snapshot_dict.get("raw", {})
            cpu_val = snapshot_dict.get("cpu_percent", 0.0)
            ram_val = snapshot_dict.get("ram_percent", 0.0)

            # Synthesize per-service distribution based on genuine device metrics
            rows = []
            services = ["auth-service", "api-gateway", "payment-gateway", "user-db", "order-service", "cache-redis"]
            for idx, s in enumerate(services):
                c_jitter = max(0.0, min(100.0, cpu_val + (idx * 2 - 5)))
                r_jitter = max(0.0, min(100.0, ram_val + (idx * 1.5 - 4)))
                lat_jitter = 40.0 + (c_jitter / 100.0) * 450.0
                err_jitter = max(0.0, (c_jitter - 75.0) / 25.0 * 15.0) if c_jitter > 75.0 else 0.5
                oss_c = compute_oss(c_jitter, r_jitter, lat_jitter)
                re_c = compute_re(oss_c, tes=0.1, dss=0.0, bcs=0.5)
                rows.append({
                    "service": s, "cpu": round(c_jitter, 1), "memory": round(r_jitter, 1),
                    "latency_ms": round(lat_jitter, 1), "error_rate": round(err_jitter, 1),
                    "re_score": round(re_c, 1)
                })
            data = pd.DataFrame(rows)
        else:
            last_updated = "No reports received yet"
            data = pd.DataFrame()

    # ── Top Banner ─────────────────────────────────────────────────────────────
    st.markdown(
        f'<div class="dashboard-card" style="padding:14px 20px;">'
        f'<div style="display:flex;justify-content:space-between;align-items:center;">'
        f'<div>'
        f'<span style="font-size:18px;font-weight:bold;color:white;">💻 {device_display_name}</span> &nbsp;'
        f'{badge_html} &nbsp;'
        f'<span style="color:#94a3b8;font-size:13px;">ID: <code>{active_id}</code> | OS: {os_display}</span>'
        f'</div>'
        f'<div style="color:#94a3b8;font-size:12px;">Last Heartbeat: <b>{last_updated}</b> | Policy: <b>{perm_key}</b></div>'
        f'</div></div>',
        unsafe_allow_html=True
    )

    if not snapshot_dict and not is_cloud_mode:
        st.warning(f"⚠️ No telemetry has been received from `{active_id}` yet. Make sure the agent is running:")
        st.code(f"python aree_agent.py --server http://localhost:8501 --device-id {active_id} --token <YOUR_TOKEN>", language="bash")
        st.stop()

    # ── KPI Cards ──────────────────────────────────────────────────────────────
    avg_re = float(data["re_score"].mean()) if not data.empty and "re_score" in data.columns else 0.0
    crit_count = int((data["re_score"] >= critical_threshold).sum()) if not data.empty else 0
    warn_count = int(((data["re_score"] >= warning_threshold) & (data["re_score"] < critical_threshold)).sum()) if not data.empty else 0
    health_score = max(0.0, 100.0 - avg_re)

    cpu_curr = snapshot_dict.get("cpu_percent", 0.0) if snapshot_dict else data["cpu"].mean() if not data.empty else 0.0
    ram_curr = snapshot_dict.get("ram_percent", 0.0) if snapshot_dict else data["memory"].mean() if not data.empty else 0.0

    k1, k2, k3, k4, k5 = st.columns(5)
    with k1:
        c_col = "#22c55e" if health_score >= 70 else "#f97316" if health_score >= 40 else "#ef4444"
        st.markdown(f'<div class="kpi-card"><div class="kpi-label">Device Health</div><div class="kpi-value" style="color:{c_col}">{health_score:.1f}%</div></div>', unsafe_allow_html=True)
    with k2:
        c_cpu = "#ef4444" if cpu_curr >= 85 else "#f97316" if cpu_curr >= 70 else "#22c55e"
        st.markdown(f'<div class="kpi-card"><div class="kpi-label">Host CPU Load</div><div class="kpi-value" style="color:{c_cpu}">{cpu_curr:.1f}%</div></div>', unsafe_allow_html=True)
    with k3:
        c_ram = "#ef4444" if ram_curr >= 90 else "#f97316" if ram_curr >= 75 else "#22c55e"
        st.markdown(f'<div class="kpi-card"><div class="kpi-label">Host RAM Usage</div><div class="kpi-value" style="color:{c_ram}">{ram_curr:.1f}%</div></div>', unsafe_allow_html=True)
    with k4:
        st.markdown(f'<div class="kpi-card"><div class="kpi-label">Active Incidents</div><div class="kpi-value" style="color:{"#ef4444" if crit_count > 0 else "#22c55e"}">{crit_count}</div></div>', unsafe_allow_html=True)
    with k5:
        st.markdown(f'<div class="kpi-card"><div class="kpi-label">Composite Risk (RE)</div><div class="kpi-value" style="color:{"#ef4444" if avg_re >= critical_threshold else "#22c55e"}">{avg_re:.1f}</div></div>', unsafe_allow_html=True)

    # ── Hardware Diagnostics Section ──────────────────────────────────────────
    if snapshot_dict:
        raw_meta = snapshot_dict.get("raw", {})
        with st.expander("🖥️ Detailed Hardware & Process Telemetry", expanded=True):
            d_col1, d_col2 = st.columns(2)
            with d_col1:
                st.markdown("**💾 Storage Mountpoints**")
                for part in raw_meta.get("disk_partitions", []):
                    u_pct = part.get("percent_used", 0)
                    col = "#ef4444" if u_pct > 90 else "#f97316" if u_pct > 75 else "#22c55e"
                    st.markdown(
                        f'<div style="margin-bottom:6px;font-size:12px;">'
                        f'<span>{part.get("mountpoint")}</span> — <b style="color:{col}">{u_pct:.1f}%</b> ({part.get("free_gb")} GB free)'
                        f'<div style="background:#1f2937;border-radius:3px;height:6px;margin-top:2px;">'
                        f'<div style="width:{min(u_pct, 100)}%;background:{col};height:100%;border-radius:3px;"></div>'
                        f'</div></div>', unsafe_allow_html=True
                    )
            with d_col2:
                st.markdown("**⚡ Running Processes (Top Resource Consumers)**")
                proc_df = pd.DataFrame(raw_meta.get("top_processes", []))
                if not proc_df.empty:
                    st.dataframe(proc_df[["pid", "name", "cpu_percent", "memory_percent", "status"]].head(6), use_container_width=True, height=160)

    # ── Active Incidents & Remote Remediation ──────────────────────────────────
    st.markdown("---")
    st.markdown("### 🚨 Device Incidents & Autonomous Self-Healing")

    device_incidents = db.get_recent_incidents(limit=10, device_id=active_id) if db else []
    if not device_incidents:
        st.success(f"✅ Zero active incidents detected on `{device_display_name}`. All thresholds healthy.")
    else:
        for inc in device_incidents:
            sev = inc.get("severity", "MEDIUM")
            css = "incident-card" + (" warning" if sev in ("MEDIUM", "HIGH") else " low" if sev == "LOW" else "")
            inc_id = inc.get("incident_id")
            res_name = inc.get("resource", "System")
            st.markdown(f"""
            <div class="{css}">
                <div style="display:flex;justify-content:space-between;">
                    <b>{res_name} — {inc.get("rule")}</b>
                    <span style="font-size:11px;background:#1e293b;padding:2px 6px;border-radius:4px;">{sev}</span>
                </div>
                <div style="font-size:13px;margin:4px 0;color:#cbd5e1;">📋 {inc.get("explanation")}</div>
                <div style="font-size:12px;color:#94a3b8;">🔍 <i>Probable Cause:</i> {inc.get("probable_cause")}</div>
                <div style="font-size:12px;color:#60a5fa;margin-top:2px;">💡 <i>Recommendation:</i> {inc.get("recommended_action")}</div>
            </div>""", unsafe_allow_html=True)

            # Manual Remote Remediation Trigger
            if perm_key in ("MANUAL", "SUGGEST") and inc.get("remediation_status") != "RESOLVED":
                r_btn1, r_btn2 = st.columns([1, 4])
                with r_btn1:
                    if st.button(f"⚡ Dispatch Safe Fix", key=f"fix-{inc_id}"):
                        task_id = f"task-{inc_id[-6:]}-{int(time.time())}"
                        action_type = "GC_COLLECT" if "RAM" in inc.get("rule", "") else "CLEAR_TEMP_FILES"
                        db.queue_remediation_task(task_id, active_id, action_type, incident_id=inc_id, dry_run=False)
                        st.success(f"Dispatched `{action_type}` directive to agent `{active_id}`!")

    # ── Visual Analytics (Gauge, Heatmap, Timeline, Graph) ────────────────────
    st.markdown("---")
    vg_col1, vg_col2 = st.columns([1, 1])

    with vg_col1:
        st.markdown("### 🩺 System Stability Index")
        if _plotly_available:
            gauge_fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=health_score,
                gauge={
                    "axis": {"range": [0, 100]},
                    "bar": {"color": "#00C896"},
                    "steps": [
                        {"range": [0, 40], "color": "#4a1010"},
                        {"range": [40, 70], "color": "#3a2a00"},
                        {"range": [70, 100], "color": "#0a2a1a"},
                    ],
                    "threshold": {"line": {"color": "#ef4444", "width": 4}, "thickness": 0.75, "value": 100 - critical_threshold}
                }
            ))
            gauge_fig.update_layout(paper_bgcolor="#020617", font={"color": "white"}, height=280, margin=dict(l=20, r=20, t=30, b=20))
            st.plotly_chart(gauge_fig, use_container_width=True)
        else:
            st.metric("Health Score", f"{health_score:.1f}%")
            st.progress(health_score / 100.0)

    with vg_col2:
        st.markdown("### 📊 Service Risk Decomposition")
        if not data.empty and "re_score" in data.columns:
            for _, r in data.sort_values("re_score", ascending=False).iterrows():
                score = r["re_score"]
                color = "#ef4444" if score >= critical_threshold else "#f97316" if score >= warning_threshold else "#22c55e"
                st.markdown(
                    f'<div style="display:flex;align-items:center;margin-bottom:8px;">'
                    f'<div style="width:140px;font-size:13px;color:#cbd5f5;">{r["service"]}</div>'
                    f'<div style="flex:1;height:10px;background:#1f2937;border-radius:5px;margin:0 10px;">'
                    f'<div style="width:{min(score, 100)}%;height:100%;background:{color};border-radius:5px;"></div></div>'
                    f'<div style="width:50px;text-align:right;font-size:12px;color:{color};font-weight:bold;">{score:.1f}</div>'
                    f'</div>', unsafe_allow_html=True)

    if _visuals_available and not data.empty:
        st.markdown("---")
        st.markdown("### 🌡️ Risk Aura Heatmap")
        try:
            h_fig = build_aura_heatmap(data, critical_threshold=critical_threshold, warning_threshold=warning_threshold)
            st.pyplot(h_fig)
        except Exception as e:
            st.warning(f"Heatmap preview: {e}")

        st.markdown("---")
        st.markdown("### 📈 Risk Energy Evolution Timeline")
        try:
            t_fig = build_timeline_chart(data, scenario="Live Operations", critical_threshold=critical_threshold, warning_threshold=warning_threshold)
            st.plotly_chart(t_fig, use_container_width=True)
        except Exception as e:
            st.warning(f"Timeline preview: {e}")

        st.markdown("---")
        st.markdown("### 🔗 Topology & Risk Propagation Graph")
        try:
            g_fig = build_dependency_graph(data, critical_threshold=critical_threshold, warning_threshold=warning_threshold)
            st.plotly_chart(g_fig, use_container_width=True)
        except Exception as e:
            st.warning(f"Graph preview: {e}")

    # ── Remediation Audit Log ─────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("### 📜 Verified Remediation Audit Ledger")
    r_logs = db.get_remediation_log(limit=15, device_id=active_id) if db else []
    if not r_logs:
        st.info(f"No self-healing operations logged yet for `{device_display_name}`.")
    else:
        for entry in r_logs:
            st.markdown(
                f'<div style="background:#0f172a;border-left:3px solid #3b82f6;padding:8px 14px;border-radius:6px;margin-bottom:6px;font-size:12px;">'
                f'<span style="color:#94a3b8;">{entry.get("timestamp")}</span> | '
                f'<b>{entry.get("action")}</b>: {entry.get("result")} '
                f'<span style="color:#64748b;">(Operator: {entry.get("operator")})</span>'
                f'</div>', unsafe_allow_html=True
            )

# ═══════════════════════════════════════════════════════════════════════════════
# FOOTER & REFRESH LOGIC
# ═══════════════════════════════════════════════════════════════════════════════

st.markdown("---")
b_c1, b_c2 = st.columns([1, 1])
with b_c1:
    if st.button("🔄 Refresh Data Now", use_container_width=True):
        st.rerun()

with b_c2:
    if _pdf_available and not is_browser_mode and not data.empty:
        if st.button("📄 Export Comprehensive Risk Report (PDF)", use_container_width=True):
            try:
                inc_df = pd.DataFrame(device_incidents) if 'device_incidents' in locals() and device_incidents else pd.DataFrame(columns=["incident_id", "severity", "resource", "explanation"])
                pdf_data = generate_pdf(data, inc_df)
                st.download_button(
                    "⬇ Download PDF",
                    data=pdf_data.read() if hasattr(pdf_data, "read") else pdf_data,
                    file_name=f"aree_report_{active_id}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                )
            except Exception as e:
                st.error(f"PDF export failed: {e}")

try:
    from streamlit.runtime import exists as _st_exists
    _in_streamlit = _st_exists()
except Exception:
    _in_streamlit = True

if _in_streamlit and auto_refresh_sec != "Off":
    delay = 5 if "5" in auto_refresh_sec else 10 if "10" in auto_refresh_sec else 30
    time.sleep(delay)
    st.rerun()

st.markdown(
    f'<div style="text-align:center;color:#475569;font-size:11px;margin-top:20px;">'
    f'AREE v2.1 Multi-Device Autonomous Risk Evolution Platform | '
    f'Active Target: {selected_option.split(" [")[0]} | '
    f'Server Time: {datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}'
    f'</div>',
    unsafe_allow_html=True
)
