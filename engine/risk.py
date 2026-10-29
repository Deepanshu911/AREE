"""
engine/risk.py — Canonical Risk Energy (RE) Engine for AREE.
============================================================

Mathematical Model:
    RE = (OSS_risk * w_oss) + (TES * w_tes) + (DSS * w_dss) + (BCS * w_bcs)

Where:
    - OSS (Operational Stability Score) ∈ [0.0, 1.0]
      Measures internal system health (CPU, RAM, latency). Higher = healthier.
    - OSS_risk = 1.0 - OSS ∈ [0.0, 1.0]
      Operational stress. Higher = higher risk (fixes legacy inversion bug).
    - TES (Threat Exposure Score) ∈ [0.0, 1.0]
      External threat exposure derived from verified threat intelligence (AbuseIPDB).
    - DSS (Dependency Spread Score) ∈ [0.0, 1.0]
      Cascading topological risk propagated across the service dependency graph.
    - BCS (Business Criticality Score) ∈ [0.0, 1.0]
      Configured weight reflecting the financial or operational importance of the asset.

Default Weights:
    w_oss = 0.35, w_tes = 0.25, w_dss = 0.25, w_bcs = 0.15 (Sum = 1.0)
    Resulting RE ∈ [0.0, 100.0]
"""
from typing import Dict, Optional, Tuple

def compute_oss(cpu_pct: float, ram_pct: float, latency_ms: float = 0.0) -> float:
    """
    Computes Operational Stability Score (OSS).
    Scale: 0.0 (total resource exhaustion / extreme latency) to 1.0 (idle / perfectly stable).
    """
    cpu_norm = max(0.0, min(float(cpu_pct) / 100.0, 1.0))
    ram_norm = max(0.0, min(float(ram_pct) / 100.0, 1.0))
    lat_norm = max(0.0, min(float(latency_ms) / 2000.0, 1.0))

    stability = 1.0 - (cpu_norm * 0.5 + ram_norm * 0.3 + lat_norm * 0.2)
    return round(max(0.0, min(1.0, stability)), 4)

def compute_re(
    oss: float,
    tes: float = 0.0,
    dss: float = 0.0,
    bcs: float = 0.5,
    weights: Tuple[float, float, float, float] = (0.35, 0.25, 0.25, 0.15),
) -> float:
    """
    Computes canonical composite Risk Energy (RE).
    Scale: 0.0 (negligible risk) to 100.0 (maximum critical risk).
    """
    # Normalize inputs to [0.0, 1.0]
    oss_val = max(0.0, min(float(oss), 1.0))
    tes_val = max(0.0, min(float(tes), 1.0))
    dss_val = max(0.0, min(float(dss), 1.0))
    bcs_val = max(0.0, min(float(bcs), 1.0))

    # Stress = 1.0 - stability
    oss_risk = 1.0 - oss_val

    # Weighted linear combination
    raw_re = (
        (oss_risk * weights[0]) +
        (tes_val * weights[1]) +
        (dss_val * weights[2]) +
        (bcs_val * weights[3])
    )

    re_score = raw_re * 100.0
    return round(max(0.0, min(100.0, re_score)), 2)

def classify_risk(re_score: float, warning: float = 45.0, critical: float = 75.0) -> str:
    """Categorizes quantitative RE score into discrete operational tiers."""
    val = float(re_score)
    if val >= critical:
        return "CRITICAL"
    if val >= warning:
        return "WARNING"
    return "STABLE"

def explain_re_score(
    oss: float,
    tes: float,
    dss: float,
    bcs: float,
    weights: Tuple[float, float, float, float] = (0.35, 0.25, 0.25, 0.15)
) -> Dict[str, float]:
    """Provides breakdown of percentage contribution of each component."""
    oss_risk = (1.0 - oss) * weights[0]
    tes_contrib = tes * weights[1]
    dss_contrib = dss * weights[2]
    bcs_contrib = bcs * weights[3]
    total = max(oss_risk + tes_contrib + dss_contrib + bcs_contrib, 0.0001)

    return {
        "operational_stress_pct": round((oss_risk / total) * 100.0, 1),
        "threat_exposure_pct": round((tes_contrib / total) * 100.0, 1),
        "dependency_spread_pct": round((dss_contrib / total) * 100.0, 1),
        "business_criticality_pct": round((bcs_contrib / total) * 100.0, 1),
    }
