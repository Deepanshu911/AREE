# ⚡ AREE — Autonomous Risk Evolution Engine (v2.1)

> **Multi-Device Real-Time System Monitoring, Cyber Risk Evolution, and Safe Autonomous Self-Healing Platform**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests Passing](https://img.shields.io/badge/tests-38%2F38%20passing-brightgreen.svg)](tests/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Deployment: Streamlit Cloud Ready](https://img.shields.io/badge/Streamlit%20Cloud-Ready-ff4b4b.svg)](ui/app.py)
[![Architecture: Safe Self--Healing](https://img.shields.io/badge/Architecture-Safe%20Self--Healing-orange.svg)](#safe-autonomous-remediation)

---

## 📌 1. Project Overview

**AREE (Autonomous Risk Evolution Engine)** is a distributed real-time cyber risk monitoring, topological incident propagation, and safe self-healing platform.

When deployed in the cloud (such as on Streamlit Community Cloud), a common pitfall is showing the cloud container's hardware metrics instead of the visitor's device. **AREE v2.1 solves this with a dual-mode multi-device architecture:**

- **Mode A (Browser-Only Status)**: Zero-install diagnostic mode for visitors opening the deployed website in a browser. It captures legitimate client capabilities (screen resolution, color depth, browser platform, hardware concurrency, network online state, navigation timings) while honestly respecting the browser sandbox boundary (no fake local CPU/disk/process claims).
- **Mode B (Full Local Device Monitoring)**: Cross-platform local agent (`aree_agent.py`) running on client laptops/servers. Communicates over authenticated single-port Tornado endpoints (`/api/v1/devices/...`) to stream genuine `psutil` metrics, detect local incidents, and execute pull-based, allowlisted self-healing playbooks.

---

## 🏗️ 2. System Architecture

```
                                  ┌──────────────────────────────────────────────────┐
                                  │               VISITOR DEVICE (LAPTOP)            │
                                  ├────────────────────────┬─────────────────────────┤
                                  │  Mode A (Web Browser)  │  Mode B (Local Agent)   │
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
│   │   • Browser Diagnostics Sandbox  │      │ • TelemetryProcessor                 │   │
│   │   • Live Gauges & Incident Feed  │      │ • Heartbeat & Task Dispatcher        │   │
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

## 📐 3. Mathematical Risk Formulation

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

## 🛡️ 4. Safe Autonomous Remediation

AREE adheres to the **Principle of Least Privilege** and defensive engineering:
- **Pull-Based Task Queue**: Remote devices poll `/api/v1/devices/telemetry` or `/heartbeat`. Remote commands are never pushed unpredictably over inbound ports.
- **Strict Allowlist**: Agents only execute verified allowlisted actions:
  - `GC_COLLECT`: Memory garbage collection on Python runtimes.
  - `CLEAR_TEMP_FILES`: Safe purge of temporary cache directories.
  - `LOWER_PROCESS_PRIORITY`: Throttling non-critical compute hogs.
- **Dry-Run by Default**: Tasks default to simulation mode unless explicitly dispatched for live execution.
- **No Arbitrary Shell Execution**: The agent rejects any command not in the allowlist.

---

## 💻 5. Quickstart & Multi-Device Usage

### A. Accessing the Deployed Streamlit Dashboard
Open the deployed AREE URL in any web browser:
1. Under **Target Device**, choose **🌐 Browser-Only Status (This Device)** to inspect your client browser's viewport, logical CPU cores, and network status without installing software.
2. The UI clearly informs you of browser sandbox boundaries and provides the enrollment command for full hardware metrics.

### B. Enrolling Your Laptop / Remote Device (Mode B)
To monitor genuine CPU, RAM, disk, processes, and run self-healing on your physical computer:

1. **Install agent prerequisites**:
```bash
pip install psutil requests
```

2. **Download or run `aree_agent.py`**:
```bash
python aree_agent.py --server https://<your-deployed-streamlit-url> --enroll --name "My-Laptop"
```
*(For local testing, default is `http://localhost:8501`)*

3. **What happens next:**
- The agent securely contacts `/api/v1/devices/enroll` and receives a salted secret Bearer token (stored locally in `aree_agent_config.json`).
- Live hardware telemetry begins streaming every 5 seconds.
- Switch to the AREE dashboard and select **`My-Laptop`** from the **Target Device** dropdown.
- You will see genuine live metrics, active local incidents, and real-time self-healing options!

---

## 🧪 6. Test Suite & Verification

Run the full automated test suite (38 unit, integration, and security tests):

```bash
pytest tests/ -v
```

### Coverage Breakdown:

| Test Module | Coverage Scope | Status |
|---|---|:---:|
| `tests/test_collector.py` | psutil hardware collection, timestamp accuracy, disk/process parsing | ✅ PASS |
| `tests/test_detector.py` | Threshold breach logic, cooldown deduplication, explanation integrity | ✅ PASS |
| `tests/test_risk_engine.py` | OSS/RE bounds, monotonicity, tier categorization, breakdown math | ✅ PASS |
| `tests/test_remediation.py` | Permission modes, dry-run safety, allowlist enforcement, gc execution | ✅ PASS |
| `tests/test_db.py` | SQLite schema creation, snapshot writes, incident state transitions | ✅ PASS |
| `tests/test_multi_device.py` | Salted token auth, HMAC verification, device isolation, task queue | ✅ PASS |
| `tests/test_dashboard.py` | UI module imports, Plotly/Matplotlib/PDF visual generators | ✅ PASS |
| `tests/test_forecaster.py` | Differential equation numerical stability, threshold breach checks | ✅ PASS |
| `tests/test_integration.py` | Full collector ➔ detector ➔ risk ➔ remediation ➔ DB lifecycle | ✅ PASS |

**Total:** 38 tests passing (100% pass rate).

---

## 🔒 7. Security & Data Privacy

- **Salted SHA-256 Token Auth**: Incoming device telemetry requires constant-time HMAC comparison against salted SHA-256 hashes (`AREE_MULTI_DEVICE_SECURITY_SALT_2026`).
- **Data Isolation**: Telemetry snapshots and incidents are strictly partitioned per `device_id` in SQLite.
- **Git Hygiene**: `.gitignore` strictly excludes local databases (`aree_data.db`), agent configurations (`aree_agent_config.json`), logs, and secrets.
- **No Intrusive Surveillance**: The agent collects only standard performance telemetry. No keystrokes, personal files, webcam, or browser histories are accessed.

---

## 📄 License
This project is licensed under the MIT License.
