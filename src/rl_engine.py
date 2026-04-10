"""
Real Q-Learning Engine for ASPM Red Team
Implements: Q(s,a) ← Q(s,a) + α[R + γ·maxQ(s',a') - Q(s,a)]
"""
import random
import math
import json
import tempfile
import os
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# Path for persisting the Q-table between scans (project root)
_QTABLE_PATH = Path(__file__).resolve().parent.parent / "qtable_state.json"


class QLearningEngine:
    """
    Genuine Q-Learning reinforcement learning agent.
    State  = (vulnerability_type, prompt_strength, temperature_band)
    Action = attack payload strategy
    Reward = +100 bypass, -1 blocked, -5 partial
    """

    ACTIONS = [
        "base_payload",
        "semantic_overload",
        "base64_encoded",
        "role_switch",
        "context_hijack",
        "nested_injection",
        "indirect_markup",
        "token_flood",
        "recursive_prompt",
        "pii_extraction",
        "jailbreak_dan",
        "temperature_exploit",
        "supply_chain_sim",
        "memory_poisoning",
        "plugin_abuse",
    ]

    def __init__(self, alpha: float = 0.15, gamma: float = 0.9, epsilon: float = 0.4):
        self.alpha   = alpha    # learning rate
        self.gamma   = gamma    # discount factor
        self.epsilon = epsilon  # exploration probability
        self.q_table: Dict[str, Dict[str, float]] = {}
        self.history: List[dict] = []
        self.episode_rewards: List[float] = []
        self.total_steps = 0

    # ── State Encoding ────────────────────────────────────────────────────────
    def encode_state(self, vuln_type: str, prompt_len: int, temperature: float) -> str:
        if prompt_len < 10:
            ps = "absent"
        elif prompt_len < 50:
            ps = "weak"
        elif prompt_len < 120:
            ps = "moderate"
        else:
            ps = "strong"

        ts = "hot" if temperature > 0.75 else "warm" if temperature > 0.45 else "cold"
        return f"{vuln_type[:5]}|{ps}|{ts}"

    # ── Q-Table Init ─────────────────────────────────────────────────────────
    def _init_state(self, state: str):
        if state not in self.q_table:
            self.q_table[state] = {a: 0.0 for a in self.ACTIONS}

    # ── Action Selection (ε-greedy) ───────────────────────────────────────────
    def choose_action(self, state: str) -> Tuple[str, str]:
        self._init_state(state)
        if random.random() < self.epsilon:
            action = random.choice(self.ACTIONS)
            strategy = "explore"
        else:
            action = max(self.q_table[state], key=self.q_table[state].get)
            strategy = "exploit"
        return action, strategy

    # ── Bellman Update ────────────────────────────────────────────────────────
    def update(self, state: str, action: str, reward: float, next_state: str) -> float:
        self._init_state(state)
        self._init_state(next_state)

        old_q = self.q_table[state][action]
        max_next_q = max(self.q_table[next_state].values())

        # Core Bellman equation
        new_q = old_q + self.alpha * (reward + self.gamma * max_next_q - old_q)
        self.q_table[state][action] = new_q

        # Decay epsilon (exploitation increases over time)
        self.epsilon = max(0.05, self.epsilon * 0.96)
        self.total_steps += 1

        delta = new_q - old_q
        self.history.append({
            "step": self.total_steps,
            "state": state,
            "action": action,
            "reward": reward,
            "old_q": round(old_q, 3),
            "new_q": round(new_q, 3),
            "delta": round(delta, 3),
            "epsilon": round(self.epsilon, 3),
        })
        self.episode_rewards.append(reward)
        return new_q

    # ── Compute Advantage ─────────────────────────────────────────────────────
    def compute_advantage(self, state: str, action: str) -> float:
        """A(s,a) = Q(s,a) - V(s)  where V(s) = mean Q over actions"""
        self._init_state(state)
        vals = list(self.q_table[state].values())
        v_s = sum(vals) / len(vals) if vals else 0.0
        return self.q_table[state][action] - v_s

    # ── Export ────────────────────────────────────────────────────────────────
    def export(self) -> dict:
        rewards = self.episode_rewards
        avg_r = sum(rewards) / len(rewards) if rewards else 0
        return {
            "q_table": self.q_table,
            "history": self.history[-30:],
            "epsilon_final": round(self.epsilon, 4),
            "total_steps": self.total_steps,
            "cumulative_reward": round(sum(rewards), 1),
            "avg_reward": round(avg_r, 2),
            "action_frequency": self._action_freq(),
        }

    def _action_freq(self) -> Dict[str, int]:
        freq: Dict[str, int] = {}
        for h in self.history:
            freq[h["action"]] = freq.get(h["action"], 0) + 1
        return freq

    # ── Persistence ──────────────────────────────────────────────────────
    def save(self, path: Optional[Path] = None) -> None:
        """Persist Q-table atomically so a crashed write never corrupts the file."""
        save_path = Path(path or _QTABLE_PATH)
        data = {
            "q_table":     self.q_table,
            "epsilon":     self.epsilon,
            "total_steps": self.total_steps,
        }
        try:
            # Write to a temp file in the same directory, then atomically rename
            tmp_fd, tmp_path = tempfile.mkstemp(
                dir=save_path.parent, prefix=".qtable_tmp_", suffix=".json"
            )
            with os.fdopen(tmp_fd, "w") as f:
                json.dump(data, f)
            os.replace(tmp_path, save_path)   # atomic on all major OSes
        except Exception as exc:
            print(f"[RL] Warning: could not persist Q-table — {exc}")

    def load(self, path: Optional[Path] = None) -> bool:
        """Load persisted Q-table. Returns True if a saved state was found."""
        load_path = Path(path or _QTABLE_PATH)
        if not load_path.exists():
            return False
        try:
            with open(load_path) as f:
                data = json.load(f)
            # Validate structure before accepting
            if not isinstance(data.get("q_table"), dict):
                return False
            self.q_table     = data["q_table"]
            self.epsilon     = max(0.05, float(data.get("epsilon", self.epsilon)))
            self.total_steps = int(data.get("total_steps", 0))
            return True
        except Exception:
            return False
