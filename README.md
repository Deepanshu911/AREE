# ⚡ AREE — Autonomous Risk Evolution Engine (v2.0)

> **Real-Time System Monitoring, Cyber Risk Evolution, and Safe Autonomous Self-Healing Platform**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests Passing](https://img.shields.io/badge/tests-31%2F31%20passing-brightgreen.svg)](tests/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Architecture: Safe Self--Healing](https://img.shields.io/badge/Architecture-Safe%20Self--Healing-orange.svg)](#safe-autonomous-remediation)

---

## 📌 1. Project Overview

**AREE (Autonomous Risk Evolution Engine)** is a real-time system monitoring, risk propagation, and safe self-healing platform for local systems and microservice topologies. 

Modern monitoring tools often display disconnected graphs of raw metrics (CPU, RAM, latency) without modeling how localized performance degradation or security exposure cascades into systemic failure. AREE bridges this gap by:
1. Continuously collecting genuine hardware telemetry (CPU, RAM, Disk, Network, Process stats) via a background monitoring agent.
2. Formulating an interpretable **Risk Energy (RE)** score combining operational stress, threat intelligence, and dependency graph propagation.
3. Modeling risk evolution dynamically using differential equation forecasting ($d(RE)/dt$).
4. Recommending and safely executing auto-remediation playbooks under strict permission policies (with full dry-run support).
5. Maintaining an auditable SQLite-backed incident and remediation ledger.

---

## 🏗️ 2. System Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                        HARDWARE TELEMETRY LAYER                        │
│   psutil (CPU, per-core, RAM, Disk I/O, Net Bandwidth, Top Processes) │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        MONITORING AGENT (agent/)                       │
│  MetricCollector ──► DetectionEngine ──► Supervisor Watcher Thread     │
│         │                    │                                         │
│         ▼                    ▼                                         │
│   SystemSnapshot         Incidents (Rule-based, Cooldown-managed)      │
└─────────┬────────────────────┬─────────────────────────────────────────┘
          │                    │
          ├────────────────────┼───────────────────┐
          ▼                    ▼                   ▼
┌──────────────────┐  ┌──────────────────┐  ┌───────────────────────────┐
│ RISK ENGINE      │  │ REMEDIATION      │  │ PERSISTENCE (store/db.py) │
│ (engine/risk.py) │  │ (engine/remed.)  │  │ SQLite: metric_snapshots, │
│ OSS + TES +      │  │ OBSERVE, SUGGEST │  │ incidents, remediation_log│
│ DSS + BCS = RE   │  │ APPROVED_AUTO    │  └───────────────────────────┘
└─────────┬────────┘  │ MANUAL approval  │
          │           └────────┬─────────┘
          ▼                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                         STREAMLIT DASHBOARD (ui/)                      │
│   Health Gauge ──► Aura Heatmap ──► Risk Timeline ──► Dependency Graph │
│   Active Incidents ──► Manual Remediation Controls ──► PDF Export      │
└────────────────────────────────────────────────────────────────────────┘
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
- **No arbitrary process termination**: The system will never terminate processes solely because of CPU spikes.
- **No arbitrary deletion**: Only approved temporary files in designated cache directories can be purged.
- **No unauthorized network reconfigurations**: Network settings and firewalls are never modified automatically.

### Permission Modes:
1. **`OBSERVE`** *(Default)*: Monitors and logs telemetry only. All remediation is strictly disabled.
2. **`SUGGEST`**: Recommends corrective playbooks and outlines rationale, awaiting human dispatch.
3. **`APPROVED_AUTO`**: Automatically executes items strictly listed on the **Safe Allowlist**:
   - Runtime garbage collection (`gc.collect()`)
   - Cleaning `__pycache__` and stale temp files
   - Process priority throttling (`psutil.BELOW_NORMAL_PRIORITY_CLASS`)
4. **`MANUAL`**: Generates interactive UI approval tokens in the dashboard before executing any action.

---

## 🚀 5. Getting Started

### Prerequisites:
- Python 3.10, 3.11, or 3.12
- Supported OS: Windows 10/11, Ubuntu 20.04+, macOS 12+

### 1. Clone & Set Up Virtual Environment:
```bash
git clone https://github.com/Deepanshu911/AREE.git
cd AREE

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate
```

### 2. Install Dependencies:
```bash
pip install -r requirements.txt
```

### 3. Environment Variables (Optional):
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Configure your optional AbuseIPDB API key and Slack bot credentials if desired.

---

## 💻 6. Running AREE

### Launch Streamlit Dashboard:
```bash
streamlit run ui/app.py
```
*Or forward via root launcher:*
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

### Run Batch Telemetry Sweep (Headless):
```bash
python monitor_batch.py
```

### Run Chaos Simulator:
```bash
python chaos_test.py
```

### Run Full Test Suite:
```bash
pytest tests/ -v
```

---

## 🧪 7. Test Coverage

The test suite covers unit and end-to-end integration contracts across all subsystems:

| Test Module | Coverage Scope | Status |
|---|---|:---:|
| `tests/test_collector.py` | psutil hardware collection, timestamp accuracy, disk/process parsing | ✅ PASS |
| `tests/test_detector.py` | Threshold breach logic, cooldown deduplication, explanation integrity | ✅ PASS |
| `tests/test_risk_engine.py` | OSS/RE bounds, monotonicity, tier categorization, breakdown math | ✅ PASS |
| `tests/test_remediation.py` | Permission modes, dry-run safety, allowlist enforcement, gc execution | ✅ PASS |
| `tests/test_db.py` | SQLite schema creation, snapshot writes, incident state transitions | ✅ PASS |
| `tests/test_forecaster.py` | Differential equation numerical stability, threshold breach checks | ✅ PASS |
| `tests/test_integration.py` | Full collector ➔ detector ➔ risk ➔ remediation ➔ DB lifecycle | ✅ PASS |

**Total:** 31 tests passed in ~2.0s.

---

## 🔒 8. Security & Data Privacy

- **No Hardcoded Credentials**: API tokens and secrets are strictly retrieved from environment variables.
- **Git Hygiene**: `.gitignore` explicitly prevents database artifacts (`*.db`), virtual environments, logs, and `.env` files from entering source control.
- **Data Minimization**: The local agent collects only system-level performance telemetry. No keystrokes, personal user documents, browsing histories, or credentials are read or stored.

---

## ⚠️ 9. Honest Transparency & Known Limitations

1. **Local Machine Scope**: In standalone desktop mode, the telemetry reflects the physical computer where AREE is executed. Distributed multi-server monitoring requires agent enrollment per host.
2. **Transparent vs. Black-box Scoring**: AREE utilizes interpretable mathematical modeling rather than opaque black-box neural networks for the base risk formula, ensuring zero hallucinated explanations during incident audits.
3. **OS-Specific Privileges**: Process priority adjustment on Linux/macOS requires standard user privileges over the owned process; system-level service manipulation requires explicit administrative authorization.

---

## 📄 License
This project is licensed under the MIT License.
