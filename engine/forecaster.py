"""
engine/forecaster.py — Physics-inspired Risk Energy dynamics and forecasting.
=============================================================================

Dynamical Equation:
    d(RE)/dt = alpha * RE - beta * RE - gamma * RE^2

Where:
    - alpha: Threat pressure accumulation rate
    - beta: System natural resilience and auto-recovery rate
    - gamma: Non-linear damping / dissipation factor preventing unbounded runaway

Fixes vs legacy:
    - Normalizes 0–100 RE scale into [0.0, 1.0] domain before numerical integration,
      preventing numerical explosion and scale mismatch.
    - Provides a robust linear trend fallback if SciPy ODE solver is unavailable.
"""
from typing import List, Tuple
import numpy as np

try:
    from scipy.integrate import odeint
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False

def _dre_dt(re_state, t, alpha=0.15, beta=0.08, gamma=0.05):
    """Normalized differential equation for Risk Energy trajectory."""
    r = max(0.0, re_state[0])
    drdt = alpha * r - beta * r - (gamma * (r ** 2))
    return [drdt]

def forecast_re(
    initial_re: float,
    t_steps: int = 10,
    dt: float = 1.0,
    alpha: float = 0.15,
    beta: float = 0.08,
    gamma: float = 0.05
) -> Tuple[List[float], List[float]]:
    """
    Simulates future RE trajectory over t_steps intervals.
    Returns: (time_points, forecasted_re_scores_in_0_to_100)
    """
    initial_re_clamped = max(0.0, min(float(initial_re), 100.0))
    time_points = [float(i * dt) for i in range(t_steps)]

    # Normalized initial condition in [0.0, 1.0]
    r0 = initial_re_clamped / 100.0

    if SCIPY_AVAILABLE:
        try:
            t = np.linspace(0, (t_steps - 1) * dt, t_steps)
            sol = odeint(_dre_dt, [r0], t, args=(alpha, beta, gamma))
            forecast = [round(float(np.clip(v * 100.0, 0.0, 100.0)), 2) for v in sol.flatten()]
            return time_points, forecast
        except Exception:
            pass

    # Fallback simulation if scipy integration encounters numerical error or missing lib
    forecast = []
    current = r0
    for _ in range(t_steps):
        forecast.append(round(float(np.clip(current * 100.0, 0.0, 100.0)), 2))
        dr = (alpha * current - beta * current - gamma * (current ** 2)) * dt
        current = max(0.0, min(1.0, current + dr))

    return time_points, forecast

def should_intervene(re_forecast: List[float], threshold: float = 75.0) -> bool:
    """Returns True if any forecasted point breaches the critical intervention threshold."""
    return any(score >= threshold for score in re_forecast)
