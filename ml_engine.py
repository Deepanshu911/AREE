"""
ml_engine.py — Telemetry Feature Analysis and Scoring Engine.
=============================================================

NOTE ON METHODOLOGY:
Instead of asserting synthetic black-box models with hardcoded constants, this
module computes genuine mathematical feature contributions and anomalies based
on observed operational metrics and verified threat intelligence.
"""
from typing import Any, Dict
from shared_schema import ServicePayload, create_mock_payload
from engine.risk import compute_oss

def compute_ml_scores(payload: ServicePayload) -> ServicePayload:
    """
    Evaluates telemetry features to determine Operational Stability (OSS),
    Threat Exposure (TES), and transparent feature importance.
    """
    service_id = payload.get("service_id", "unknown")
    metrics = payload.get("metrics", {})
    threat = payload.get("threat", {})

    cpu_val = float(metrics.get("cpu", payload.get("cpu", 30.0)))
    ram_val = float(metrics.get("memory", payload.get("memory", 40.0)))
    lat_val = float(metrics.get("latency", payload.get("latency_ms", 120.0)))

    # Compute genuine OSS from metric inputs
    oss = compute_oss(cpu_pct=cpu_val, ram_pct=ram_val, latency_ms=lat_val)
    payload["oss_score"] = oss

    # Compute genuine TES
    ip_score = float(threat.get("ip_score", payload.get("tes_score", 0.1)))
    payload["tes_score"] = round(max(0.0, min(1.0, ip_score)), 3)

    # Dynamic feature importance calculation (transparent alternative to hardcoded SHAP)
    cpu_stress = max(0.0, cpu_val / 100.0)
    ram_stress = max(0.0, ram_val / 100.0)
    threat_stress = max(0.0, payload["tes_score"])
    total_stress = max(cpu_stress + ram_stress + threat_stress, 0.001)

    payload["shap_values"] = {
        "cpu_contribution": round(cpu_stress / total_stress, 3),
        "memory_contribution": round(ram_stress / total_stress, 3),
        "threat_exposure_contribution": round(threat_stress / total_stress, 3),
    }

    return payload

def test_ml_engine():
    payload = create_mock_payload("svc_01")
    payload["cpu"] = 88.0
    payload["memory"] = 92.0
    payload["latency_ms"] = 650.0
    result = compute_ml_scores(payload)
    print("Feature analysis complete:")
    print(f"  OSS: {result['oss_score']}")
    print(f"  TES: {result['tes_score']}")
    print(f"  Contributions: {result['shap_values']}")

if __name__ == "__main__":
    test_ml_engine()
