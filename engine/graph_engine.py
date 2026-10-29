"""
engine/graph_engine.py — Topological risk propagation across service dependencies.
==================================================================================

Computes Dependency Spread Score (DSS):
    DSS = sum(child_RE * decay^depth) / num_children / 100.0

Where:
    - decay: 0.8 per hop attenuation
    - max_depth: 3 levels of recursive topological propagation
"""
from typing import Dict, List, Optional
import networkx as nx

DEFAULT_SERVICES = [
    "api-gateway", "auth-service", "payment-service",
    "db-primary", "db-replica", "redis-cache",
    "notification-service", "ml-model-service"
]

DEFAULT_EDGES = [
    ("api-gateway", "auth-service"),
    ("api-gateway", "payment-service"),
    ("payment-service", "db-primary"),
    ("db-primary", "db-replica"),
    ("auth-service", "redis-cache"),
    ("payment-service", "notification-service"),
    ("ml-model-service", "api-gateway"),
    ("db-primary", "redis-cache"),
]

def build_service_graph(
    services: Optional[List[str]] = None,
    edges: Optional[List[tuple]] = None
) -> nx.DiGraph:
    """Builds the directed service dependency graph."""
    G = nx.DiGraph()
    G.add_nodes_from(services or DEFAULT_SERVICES)
    G.add_edges_from(edges or DEFAULT_EDGES)
    return G

def compute_dss_graph(
    G: nx.DiGraph,
    service_re_map: Dict[str, float],
    node: str,
    depth: int = 0,
    max_depth: int = 3,
    decay: float = 0.8
) -> float:
    """
    Recursively computes the Dependency Spread Score (DSS) for a given service node.
    Returns a normalized value in [0.0, 1.0].
    """
    if not G.has_node(node) or depth >= max_depth:
        return 0.0

    children = list(G.successors(node))
    if not children:
        return 0.0

    child_scores = []
    for child in children:
        child_re = float(service_re_map.get(child, 0.0))
        # Direct risk contribution discounted by depth decay
        propagated = child_re * (decay ** depth)
        # Downstream cascade
        propagated += compute_dss_graph(G, service_re_map, child, depth + 1, max_depth, decay) * 100.0
        child_scores.append(propagated)

    if not child_scores:
        return 0.0

    avg_cascading_score = sum(child_scores) / len(child_scores)
    # Normalize to [0.0, 1.0]
    return round(min(1.0, max(0.0, avg_cascading_score / 100.0)), 4)
