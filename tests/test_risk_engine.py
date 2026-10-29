"""
tests/test_risk_engine.py — Unit tests for canonical risk calculations.
"""
import pytest
from engine.risk import compute_oss, compute_re, classify_risk, explain_re_score

class TestComputeOSS:
    def test_zero_load_maximum_stability(self):
        oss = compute_oss(cpu_pct=0.0, ram_pct=0.0, latency_ms=0.0)
        assert oss == 1.0

    def test_full_load_zero_stability(self):
        oss = compute_oss(cpu_pct=100.0, ram_pct=100.0, latency_ms=2000.0)
        assert oss == 0.0

    def test_oss_clamped_bounds(self):
        # Exceeding normal ranges
        assert compute_oss(cpu_pct=150.0, ram_pct=200.0, latency_ms=5000.0) == 0.0
        assert compute_oss(cpu_pct=-20.0, ram_pct=-10.0, latency_ms=-50.0) == 1.0

    def test_higher_cpu_reduces_stability(self):
        low = compute_oss(cpu_pct=20.0, ram_pct=40.0)
        high = compute_oss(cpu_pct=85.0, ram_pct=40.0)
        assert high < low

class TestComputeRE:
    def test_healthy_idle_system_low_risk(self):
        # Perfect stability (oss=1.0), no threat, no cascade, moderate BCS
        re = compute_re(oss=1.0, tes=0.0, dss=0.0, bcs=0.5)
        # oss_risk = 0 -> only bcs * 0.15 = 7.5
        assert re == 7.5
        assert classify_risk(re) == "STABLE"

    def test_failing_system_maximum_risk(self):
        # Total instability (oss=0.0), critical threat, severe cascade, highest BCS
        re = compute_re(oss=0.0, tes=1.0, dss=1.0, bcs=1.0)
        assert re == 100.0
        assert classify_risk(re) == "CRITICAL"

    def test_re_boundary_invariance(self):
        for oss in [0.0, 0.25, 0.5, 0.75, 1.0]:
            for tes in [0.0, 0.5, 1.0]:
                re = compute_re(oss=oss, tes=tes, dss=0.2, bcs=0.5)
                assert 0.0 <= re <= 100.0

    def test_fixed_semantic_inversion(self):
        """Validates that declining stability increases risk (bug fix)."""
        re_healthy = compute_re(oss=0.9, tes=0.2, dss=0.1, bcs=0.5)
        re_stressed = compute_re(oss=0.1, tes=0.2, dss=0.1, bcs=0.5)
        assert re_stressed > re_healthy

class TestClassifyRisk:
    def test_threshold_tiers(self):
        assert classify_risk(25.0) == "STABLE"
        assert classify_risk(45.0) == "WARNING"
        assert classify_risk(60.0) == "WARNING"
        assert classify_risk(75.0) == "CRITICAL"
        assert classify_risk(90.0) == "CRITICAL"

class TestExplainRE:
    def test_contribution_percentages_sum_to_100(self):
        breakdown = explain_re_score(oss=0.4, tes=0.6, dss=0.3, bcs=0.5)
        total = sum(breakdown.values())
        assert abs(total - 100.0) < 1.0
