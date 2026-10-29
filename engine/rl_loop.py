"""
engine/rl_loop.py — Tabular Q-learning agent for adaptive incident action recommendations.
========================================================================================

State Space (3 x 3 = 9 states):
    - Risk Bucket: 0=LOW (RE < 45), 1=MEDIUM (45 <= RE <= 75), 2=HIGH (RE > 75)
    - Trend: 0=STABLE (|delta| <= 2), 1=RISING (delta > 2), 2=FALLING (delta < -2)

Action Space (4 actions):
    - MONITOR, ALERT, SCALE_UP, ISOLATE

Fixes vs legacy:
    - Fixed next_state bug where get_state(re, re) always produced trend=0.
    - Added JSON persistence for Q-table so learned weights survive process restarts.
"""
import json
import logging
import os
from pathlib import Path
import random
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

ACTIONS = ["MONITOR", "ALERT", "SCALE_UP", "ISOLATE"]
DEFAULT_QTABLE_PATH = Path(__file__).parent / "qtable.json"

_Q_TABLE: Dict[str, float] = {}

def get_state(re_score: float, prev_re: float) -> Tuple[int, int]:
    """Discretizes continuous RE trajectory into (risk_bucket, trend)."""
    if re_score > 75.0:
        bucket = 2  # HIGH
    elif re_score >= 45.0:
        bucket = 1  # MEDIUM
    else:
        bucket = 0  # LOW

    delta = re_score - prev_re
    if delta > 2.0:
        trend = 1   # RISING
    elif delta < -2.0:
        trend = 2   # FALLING
    else:
        trend = 0   # STABLE

    return (bucket, trend)

def _state_action_key(state: Tuple[int, int], action: str) -> str:
    return f"{state[0]}_{state[1]}:{action}"

def get_q(state: Tuple[int, int], action: str) -> float:
    return _Q_TABLE.get(_state_action_key(state, action), 0.0)

def best_action(state: Tuple[int, int]) -> str:
    """Selects greedily optimal action according to learned Q-values."""
    return max(ACTIONS, key=lambda a: get_q(state, a))

def compute_reward(re_score: float, action: str) -> float:
    """Evaluates the alignment of an action with the observed risk posture."""
    if re_score > 75.0:
        if action == "ISOLATE":   return +15.0
        if action == "SCALE_UP":  return +10.0
        if action == "ALERT":     return +2.0
        if action == "MONITOR":   return -15.0
    elif re_score >= 45.0:
        if action == "ALERT":     return +10.0
        if action == "SCALE_UP":  return +5.0
        if action == "ISOLATE":   return -5.0
        if action == "MONITOR":   return -2.0
    else:
        if action == "MONITOR":   return +10.0
        if action == "ALERT":     return -2.0
        if action == "ISOLATE":   return -15.0
        if action == "SCALE_UP":  return -5.0
    return 0.0

def update_q(
    state: Tuple[int, int],
    action: str,
    reward: float,
    next_state: Tuple[int, int],
    alpha: float = 0.1,
    gamma: float = 0.9
) -> None:
    """Applies Bellman equation update."""
    curr_q = get_q(state, action)
    max_next_q = max(get_q(next_state, a) for a in ACTIONS)
    new_q = curr_q + alpha * (reward + (gamma * max_next_q) - curr_q)
    _Q_TABLE[_state_action_key(state, action)] = round(new_q, 4)

def rl_decide(
    re_score: float,
    prev_re: float,
    explore: bool = False,
    epsilon: float = 0.15
) -> Tuple[str, float]:
    """
    Returns recommended action and immediate reward.
    Updates the Q-table based on estimated future trajectory.
    """
    state = get_state(re_score, prev_re)

    if explore and random.random() < epsilon:
        action = random.choice(ACTIONS)
    else:
        action = best_action(state)

    reward = compute_reward(re_score, action)

    # Estimate expected transition post-action
    if action in ("ISOLATE", "SCALE_UP"):
        projected_re = max(0.0, re_score - 15.0)
    elif action == "ALERT":
        projected_re = max(0.0, re_score - 2.0)
    else:
        projected_re = re_score + (2.0 if state[1] == 1 else 0.0)

    next_state = get_state(projected_re, re_score)
    update_q(state, action, reward, next_state)

    return action, reward

def save_qtable(path: Optional[Path] = None) -> None:
    target = path or DEFAULT_QTABLE_PATH
    try:
        with open(target, "w", encoding="utf-8") as f:
            json.dump(_Q_TABLE, f, indent=2)
    except Exception as e:
        logger.warning("Failed to save Q-table: %s", e)

def load_qtable(path: Optional[Path] = None) -> None:
    global _Q_TABLE
    target = path or DEFAULT_QTABLE_PATH
    if target.exists():
        try:
            with open(target, "r", encoding="utf-8") as f:
                _Q_TABLE = json.load(f)
        except Exception as e:
            logger.warning("Failed to load Q-table: %s", e)

# Load existing weights on import if available
load_qtable()
