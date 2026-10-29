"""
re_engine.py — Root bridge to canonical risk calculation.
"""
from ui.re_engine import compute_re_score, compute_re_pipeline

if __name__ == "__main__":
    res = compute_re_score("payment-service", 250.0)
    print("re_engine root:", res)
