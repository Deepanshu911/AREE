"""
aree/re_engine.py — Bridge to canonical risk calculation.
"""
import sys, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from engine.risk import compute_oss as _canonical_oss, compute_re as _canonical_re
from engine.graph_engine import build_service_graph, compute_dss_graph

G = build_service_graph()

def compute_oss(metrics):
    cpu = metrics.get('cpu', 0.0)
    # If cpu is given in 0.0-1.0, convert to 0-100
    if cpu <= 1.0:
        cpu = cpu * 100.0
    latency = metrics.get('latency', 0.0)
    return _canonical_oss(cpu_pct=cpu, ram_pct=30.0, latency_ms=latency)

def compute_tes(threat):
    return round(float(threat.get('ip_score', 0.0)), 4)

def compute_dss(service_re_map=None, node="api-gateway"):
    if service_re_map is None:
        return 0.5
    return compute_dss_graph(G, service_re_map, node)

def compute_bcs():
    return 0.5

def compute_re(oss, tes, dss=None, bcs=None, weights=None):
    dss_val = 0.5 if dss is None else dss
    bcs_val = compute_bcs() if bcs is None else bcs
    w = (0.35, 0.25, 0.25, 0.15) if weights is None else tuple(weights)
    return _canonical_re(oss=oss, tes=tes, dss=dss_val, bcs=bcs_val, weights=w)

if __name__ == "__main__":
    oss = compute_oss({"cpu": 0.85, "latency": 400})
    tes = compute_tes({"ip_score": 0.9})
    re = compute_re(oss, tes)
    print(f"OSS: {oss}, TES: {tes}, RE: {re}")
