"""
ui/re_engine.py — Bridge to canonical risk calculation.
Maintains backward compatibility while routing calculations through engine.risk.
"""
import sys, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import numpy as np
from shared_schema import create_mock_payload, ServicePayload
from engine.risk import compute_oss, compute_re, classify_risk

def compute_re_score(service: str, latency: float):
    """Legacy signature maintaining backward compatibility."""
    oss = compute_oss(cpu_pct=30.0, ram_pct=40.0, latency_ms=latency)
    tes = 0.3
    # compute_re gives 0-100
    re_score_100 = compute_re(oss=oss, tes=tes, dss=0.0, bcs=0.5)
    re_score = re_score_100 / 100.0

    if re_score > 0.7:
        aura_level, action = "🔴 RED", "🚨 AUTO-REMEDIATE"
    elif re_score > 0.4:
        aura_level, action = "🟠 ORANGE", "⚠️ WARNING"
    else:
        aura_level, action = "🟢 GREEN", "✅ MONITOR"

    return {
        "service": service, "oss": oss, "tes": tes,
        "re_score": re_score, "aura_level": aura_level, "action": action
    }

def compute_re_pipeline(payload: ServicePayload):
    """Pipeline signature integrating canonical engine."""
    oss = float(payload.get("oss_score", 0.8))
    tes = float(payload.get("tes_score", 0.2))
    
    # Canonical calculation: 0-100 scale, normalized to [0, 1] for payload consistency
    re_100 = compute_re(oss=oss, tes=tes, dss=0.0, bcs=0.5)
    payload["re_score"] = round(re_100 / 100.0, 4)

    tier = classify_risk(re_100, warning=45.0, critical=75.0)
    if tier == "CRITICAL":
        payload["aura_level"] = "🔴 RED"
    elif tier == "WARNING":
        payload["aura_level"] = "🟠 ORANGE"
    else:
        payload["aura_level"] = "🟢 GREEN"

    return payload

if __name__ == "__main__":
    test_res = compute_re_score("auth-service", 450.0)
    print("Bridge RE calculation:", test_res)
