# ⚡ AREE — Autonomous Risk Evolution Engine (v2.1)

> **Public Multi-Device Cyber Risk Monitoring & Safe Autonomous Self-Healing Platform**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests Passing](https://img.shields.io/badge/tests-43%2F43%20passing-brightgreen.svg)](tests/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Deployment: Streamlit Cloud Ready](https://img.shields.io/badge/Streamlit%20Cloud-Ready-ff4b4b.svg)](ui/app.py)
[![Architecture: Safe Self--Healing](https://img.shields.io/badge/Architecture-Safe%20Self--Healing-orange.svg)](#safe-autonomous-remediation)

---

## 📌 1. Project Overview & Public Visitor Mode

**AREE (Autonomous Risk Evolution Engine)** is a public, multi-device cyber risk monitoring, topological risk propagation, and safe self-healing platform.

### 🌟 The Core Zero-Install Visitor Guarantee
When you share your deployed Streamlit URL with another person, **anyone who opens the link on their laptop immediately sees information about THEIR OWN device, not your laptop's metrics.**

The visitor does **NOT** have to:
- ❌ Install Python, pip, or any software.
- ❌ Download or run any background agent.
- ❌ Open Terminal, CMD, or PowerShell.
- ❌ Copy-paste commands, tokens, or scripts.
- ❌ Manually configure device settings.
- ❌ Copy any files from the developer's computer.

**The only action required from any visitor is opening the website link in their web browser.**

---

## 🏗️ 2. Dual-Mode Architecture

```
                                  ┌──────────────────────────────────────────────────┐
                                  │               VISITOR DEVICE (LAPTOP)            │
                                  ├────────────────────────┬─────────────────────────┤
                                  │  Mode A (Web Browser)  │  Mode B (Local Agent)   │
                                  │  • Zero-Install Default│  • Optional Advanced    │
                                  │  • Viewport & Cores    │  • psutil Telemetry     │
                                  │  • Online/Offline state│  • Processes & Disks    │
                                  │  • Sandbox Boundary    │  • Safe Self-Healing    │
                                  └───────────┬────────────┴────────────┬────────────┘
                                              │                         │
                          HTTPS (HTML/JS)     │      HTTPS (Token Auth) │
                                              │      /api/v1/devices/*  │
                                              ▼                         ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        AREE DEPLOYED SERVER (STREAMLIT / TORNADO)                      │
│                                                                                        │
│   ┌──────────────────────────────────┐      ┌──────────────────────────────────────┐   │
│   │   Streamlit Web UI (ui/app.py)   │      │ Tornado Mounted Ingest (/server)     │   │
│   │   • Target Device Selector       │◄─────┤ • DeviceManager (HMAC Salted Auth)   │   │
│   │   • Browser Diagnostics Console  │      │ • TelemetryProcessor                 │   │
│   │   • Honest Capability Matrix     │      │ • Heartbeat & Task Dispatcher        │   │
│   └─────────────────┬────────────────┘      └──────────────────┬───────────────────┘   │
│                     │                                          │                       │
│                     ├──────────────────────────────────────────┘                       │
│                     ▼                                                                  │
│   ┌──────────────────────────────────┐      ┌──────────────────────────────────────┐   │
│   │ Canonical Risk Engine (OSS/RE)   │      │ Thread-Safe Persistence (store/db.py)│   │
│   │ RE = (OSS_risk*0.35 + TES*0.25   │      │ • devices registry                   │   │
│   │     + DSS*0.25 + BCS*0.15) * 100 │      │ • metric_snapshots (isolated/device) │   │
│   └──────────────────────────────────┘      │ • incidents & device_tasks queue     │   │
│                                             └──────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🛡️ 3. Honest Browser Sandbox & Capabilities Matrix

Modern cybersecurity requires complete transparency in telemetry. A normal website cannot directly access complete operating-system CPU utilization, total physical RAM, storage partitions, or background processes without native privileges.

**AREE never fabricates data or labels mock values as real.** In Visitor Mode, the dashboard displays only metrics genuinely available through standard browser APIs, and explicitly designates protected host metrics:

| System Metric | Status in Browser Mode | Value / Reading | Architectural Sandbox Boundary |
|---|---|---|---|
| **Client OS & Platform** | 🟢 **Observed** | Detected via User-Agent & Client Hints | Standard Web Browser API |
| **Logical CPU Cores** | 🟢 **Observed** | `navigator.hardwareConcurrency` | Available via browser runtime |
| **Screen & Viewport** | 🟢 **Observed** | `window.screen` & `window.innerWidth/Height` | Viewport dimensions available to layout engine |
| **Network Connectivity** | 🟢 **Observed** | `navigator.onLine` & Network Info API | Real-time browser connection state |
| **Page Performance & Timings** | 🟢 **Observed** | Navigation Timing & Performance API | DOM lifecycle & network transit duration |
| **Device Memory (Approx)** | 🟡 **Restricted** | Coarse-grained tier (e.g. 8 GiB) | Coarse tier only (prevent browser fingerprinting) |
| **Host CPU Utilization %** | 🔒 **Not Available in Browser Mode** | `N/A (Browser Sandbox Restriction)` | Browser sandbox isolates web apps from OS scheduler |
| **Physical RAM & Swap** | 🔒 **Not Available in Browser Mode** | `N/A (Browser Sandbox Restriction)` | Direct kernel virtual memory access requires OS privileges |
| **Local Storage Partitions** | 🔒 **Not Available in Browser Mode** | `N/A (Browser Sandbox Restriction)` | Origin policy forbids inspecting host disk partitions or I/O |
| **Running Background Processes** | 🔒 **Not Available in Browser Mode** | `N/A (Browser Sandbox Restriction)` | Inspecting OS process tables requires process management rights |
| **Raw Network Socket Sniffing** | 🔒 **Not Available in Browser Mode** | `N/A (Browser Sandbox Restriction)` | Raw socket capture is restricted by TCP/IP stack & CORS |

---

## 📐 4. Mathematical Risk Formulation

The canonical Risk Energy (RE) score is a normalized scalar value bounded strictly in $[0.0, 100.0]$:

$$\text{RE} = \left( \text{OSS}_{\text{risk}} \cdot 0.35 + \text{TES} \cdot 0.25 + \text{DSS} \cdot 0.25 + \text{BCS} \cdot 0.15 \right) \times 100$$

### Components:
- **$\text{OSS}$ (Operational Stability Score)** $\in [0.0, 1.0]$:
  $$\text{OSS} = 1.0 - \left( \frac{\text{CPU}\%}{100} \cdot 0.5 + \frac{\text{RAM}\%}{100} \cdot 0.3 + \min\left(\frac{\text{Latency}}{2000\text{ms}}, 1.0\right) \cdot 0.2 \right)$$
- **$\text{OSS}_{\text{risk}}$**:
  $$\text{OSS}_{\text{risk}} = 1.0 - \text{OSS}$$
  *(Ensures that operational degradation directly drives risk upward).*
- **$\text{TES}$ (Threat Exposure Score)** $\in [0.0, 1.0]$:
  Derived from real-time IP abuse confidence scores via AbuseIPDB API.
- **$\text{DSS}$ (Dependency Spread Score)** $\in [0.0, 1.0]$:
  Topological cascading risk propagated across directed NetworkX dependency graph with exponential attenuation:
  $$\text{DSS}(u) = \frac{1}{|children(u)|} \sum_{v \in children(u)} \left( \text{RE}(v) \cdot 0.8^{\text{depth}} \right)$$
- **$\text{BCS}$ (Business Criticality Score)** $\in [0.0, 1.0]$:
  Configurable asset priority rating (default $0.5$).

### Risk Tiers:
- **🟢 STABLE**: $\text{RE} < 45.0$
- **🟠 WARNING**: $45.0 \le \text{RE} < 75.0$
- **🔴 CRITICAL**: $\text{RE} \ge 75.0$

---

## 🛡️ 5. Safe Autonomous Remediation (Agent Mode)

For administrators who enroll computers via the optional standalone agent:
- **Pull-Based Task Queue**: Remote devices poll `/api/v1/devices/telemetry` or `/heartbeat`. Remote commands are never pushed unpredictably over inbound ports.
- **Strict Allowlist**: Agents only execute verified allowlisted actions:
  - `GC_COLLECT`: Memory garbage collection on Python runtimes.
  - `CLEAR_TEMP_FILES`: Safe purge of temporary cache directories.
  - `LOWER_PROCESS_PRIORITY`: Throttling non-critical compute hogs.
- **Dry-Run by Default**: Tasks default to simulation mode unless explicitly dispatched for live execution.
- **No Arbitrary Shell Execution**: The agent rejects any command not in the allowlist.

---

## 💻 6. Quickstart & Multi-Device Usage

### A. Public Visitor View (Zero Install)
Simply share your deployed Streamlit URL (e.g. `https://<your-app>.streamlit.app`).
1. Any visitor who opens the link immediately sees their own browser session: `👤 My Device [vis-xxxx] (Browser-Only Mode)`.
2. Their browser model, operating system, logical cores, display resolution, active viewport, network reachability, and page load latency are detected automatically.
3. Multiple visitors receive isolated sessions simultaneously with zero data leakage.

### B. Optional: Enrolling a Computer for Full Host OS Monitoring (Mode B)
If you specifically want to stream complete host operating system CPU load, RAM usage, storage mountpoints, top processes, and run self-healing:

1. **Install agent prerequisites**:
```bash
pip install psutil requests
```

2. **Run `aree_agent.py` pointing to your deployed Streamlit URL**:
```bash
python aree_agent.py --server https://<your-deployed-streamlit-url> --enroll --name "Work-Laptop"
```

3. **What happens next**:
- The agent enrolls and streams genuine hardware telemetry every 5 seconds.
- The computer appears in the dashboard's **Target Device** dropdown for real-time monitoring and safe auto-remediation.

---

## 🧪 7. Test Suite & Verification

Run the full automated test suite (43 unit, integration, visitor mode, and multi-device security tests):

```bash
pytest tests/ -v
```

### Coverage Breakdown:

| Test Module | Coverage Scope | Status |
|---|---|:---:|
| `tests/test_visitor_mode.py` | Auto session creation, visitor isolation, no fake metrics, XSS/rate limiting | ✅ PASS |
| `tests/test_collector.py` | psutil hardware collection, timestamp accuracy, disk/process parsing | ✅ PASS |
| `tests/test_detector.py` | Threshold breach logic, cooldown deduplication, explanation integrity | ✅ PASS |
| `tests/test_risk_engine.py` | OSS/RE bounds, monotonicity, tier categorization, breakdown math | ✅ PASS |
| `tests/test_remediation.py` | Permission modes, dry-run safety, allowlist enforcement, gc execution | ✅ PASS |
| `tests/test_db.py` | SQLite schema creation, snapshot writes, incident state transitions | ✅ PASS |
| `tests/test_multi_device.py` | Salted token auth, HMAC verification, device isolation, task queue | ✅ PASS |
| `tests/test_dashboard.py` | UI module imports, Plotly/Matplotlib/PDF visual generators | ✅ PASS |
| `tests/test_forecaster.py` | Differential equation numerical stability, threshold breach checks | ✅ PASS |
| `tests/test_integration.py` | Full collector ➔ detector ➔ risk ➔ remediation ➔ DB lifecycle | ✅ PASS |

**Total:** 43 tests passing (100% pass rate).

---

## 🔒 8. Security & Data Privacy

- **Session Isolation**: Each web visitor is assigned a cryptographically random session ID (`vis-xxxxxxxx`). No shared in-memory dictionaries or database records leak between visitors.
- **Input Sanitization & Rate Limiting**: All client-side parameters are HTML-escaped and bounded, and updates are rate limited to 1 per 0.5s to prevent flooding.
- **Salted SHA-256 Token Auth**: Enrolled agent telemetry requires constant-time HMAC comparison against salted SHA-256 hashes (`AREE_MULTI_DEVICE_SECURITY_SALT_2026`).
- **No Intrusive Surveillance**: The agent collects only standard performance telemetry. No keystrokes, personal files, webcam, or browser histories are accessed.

---

## 📄 License
This project is licensed under the MIT License.
