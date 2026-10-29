"""
aree/rl_loop.py — Bridge to canonical RL loop with persistent Q-table.
"""
import sys, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from engine.rl_loop import (
    ACTIONS,
    get_state,
    get_q,
    best_action,
    update_q,
    compute_reward,
    rl_decide,
    save_qtable,
    load_qtable,
)

if __name__ == "__main__":
    action, reward = rl_decide(78.5, 72.0, explore=False)
    print(f"RL Decision for rising high risk: {action} (Reward={reward})")
