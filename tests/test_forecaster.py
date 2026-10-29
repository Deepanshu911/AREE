"""
tests/test_forecaster.py — Unit tests for forecasting logic and threshold alerts.
"""
from engine.forecaster import forecast_re, should_intervene

class TestForecaster:
    def test_forecast_stays_within_bounds(self):
        for start_re in [0.0, 25.0, 50.0, 75.0, 100.0]:
            t, f = forecast_re(initial_re=start_re, t_steps=10)
            assert len(t) == 10
            assert len(f) == 10
            for val in f:
                assert 0.0 <= val <= 100.0

    def test_should_intervene_behavior(self):
        assert should_intervene([40.0, 50.0, 60.0], threshold=75.0) is False
        assert should_intervene([40.0, 70.0, 80.0], threshold=75.0) is True

    def test_initial_point_matches(self):
        _, f = forecast_re(initial_re=55.0, t_steps=5)
        # First point should approximate starting RE
        assert abs(f[0] - 55.0) < 1.0
