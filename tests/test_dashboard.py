"""
tests/test_dashboard.py — Validates dashboard imports and visual component generation.
"""
import pandas as pd
import pytest

def test_ui_app_imports_cleanly():
    """Ensures ui/app.py has no broken top-level imports or syntax errors."""
    import ui.app
    assert hasattr(ui.app, "SERVICES")
    assert len(ui.app.SERVICES) > 0

def test_visual_components_render():
    """Verifies graph, timeline, and heatmap chart generators execute cleanly."""
    from visuals.graph_view import build_dependency_graph
    from visuals.timeline import build_timeline_chart
    from visuals.heatmap import build_aura_heatmap
    from utils.pdf_export import generate_pdf

    mock_df = pd.DataFrame([
        {"service": "api-gateway", "re_score": 42.0, "cpu": 35.0, "memory": 50.0, "error_rate": 2.0, "latency_ms": 150.0},
        {"service": "auth-service", "re_score": 68.0, "cpu": 65.0, "memory": 70.0, "error_rate": 5.0, "latency_ms": 320.0},
        {"service": "payment-gateway", "re_score": 82.0, "cpu": 88.0, "memory": 92.0, "error_rate": 18.0, "latency_ms": 850.0},
    ])

    # 1. Dependency Graph (Plotly)
    graph_fig = build_dependency_graph(mock_df, critical_threshold=75.0, warning_threshold=45.0)
    assert graph_fig is not None

    # 2. Timeline (Plotly)
    timeline_fig = build_timeline_chart(mock_df, scenario="Normal Operations", critical_threshold=75.0, warning_threshold=45.0)
    assert timeline_fig is not None

    # 3. Aura Heatmap (Matplotlib)
    heatmap_fig = build_aura_heatmap(mock_df, critical_threshold=75.0, warning_threshold=45.0)
    assert heatmap_fig is not None

    # 4. PDF Generation (ReportLab)
    incidents_df = pd.DataFrame([
        {"incident_id": "test-1", "severity": "CRITICAL", "resource": "payment-gateway", "explanation": "High latency"}
    ])
    pdf_buffer = generate_pdf(mock_df, incidents_df)
    assert pdf_buffer is not None
    assert pdf_buffer.getbuffer().nbytes > 0
