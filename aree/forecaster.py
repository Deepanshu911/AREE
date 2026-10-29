"""
aree/forecaster.py — Bridge to canonical physics-based forecaster.
"""
import sys, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from engine.forecaster import forecast_re, should_intervene

if __name__ == "__main__":
    t, forecast = forecast_re(initial_re=64.58, t_steps=15)
    print("=" * 40)
    print("  RE Forecast (15 steps):")
    for time, re in zip(t, forecast):
        bar = "█" * int(re / 5)
        print(f"  t={time:.1f} → RE={re:.2f} {bar}")
    print("=" * 40)
    print(f"  Intervene? {should_intervene(forecast)}")
    print("=" * 40)
