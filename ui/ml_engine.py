"""
ui/ml_engine.py — Telemetry Feature Analysis and Scoring Engine.
"""
import sys, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from ml_engine import compute_ml_scores, test_ml_engine

if __name__ == "__main__":
    test_ml_engine()
