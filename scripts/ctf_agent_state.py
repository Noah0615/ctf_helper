"""CTF Helper v2.0 - Agent Session State & Hypothesis Management."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
import json
import uuid


@dataclass
class Hypothesis:
    id: str
    title: str
    reason: str
    expected_observation: str
    next_tool: str
    status: str = "pending"  # pending, testing, confirmed, refuted, abandoned
    evidence_ids: list[str] = field(default_factory=list)
    stagnation_count: int = 0

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Hypothesis":
        return cls(**data)


@dataclass
class SessionState:
    run_id: str
    root_id: str
    category: str = "auto"
    goal: str = "Find and verify the genuine CTF flag"
    confirmed_facts: list[str] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    active_hypothesis_id: str | None = None
    attempts: list[dict] = field(default_factory=list)
    artifacts: list[dict] = field(default_factory=list)
    budgets: dict = field(default_factory=lambda: {
        "max_steps": 25,
        "current_step": 0,
        "http_direct_requests": 0,
        "http_direct_limit": 8,
        "http_batch_requests": 0,
        "http_batch_limit": 300,
        "tcp_requests": 0,
        "tcp_limit": 8,
        "tool_calls": 0,
    })
    status: str = "INGEST"  # INGEST, PLAN, ACT, OBSERVE, VERIFY, REPLAN, SOLVED, UNRESOLVED, BUDGET_EXHAUSTED, PAUSED
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def get_active_hypothesis(self) -> Hypothesis | None:
        if not self.active_hypothesis_id:
            for h in self.hypotheses:
                if h.status in {"pending", "testing"}:
                    self.active_hypothesis_id = h.id
                    return h
            return None
        for h in self.hypotheses:
            if h.id == self.active_hypothesis_id:
                return h
        return None

    def add_hypothesis(self, title: str, reason: str, expected_observation: str, next_tool: str) -> Hypothesis:
        # Enforce max 3 hypotheses active at a time to maintain focus for 8B model
        h_id = f"hyp_{len(self.hypotheses) + 1}_{uuid.uuid4().hex[:4]}"
        h = Hypothesis(
            id=h_id,
            title=title[:200],
            reason=reason[:400],
            expected_observation=expected_observation[:300],
            next_tool=next_tool[:100],
            status="pending"
        )
        self.hypotheses.append(h)
        if not self.active_hypothesis_id:
            self.active_hypothesis_id = h.id
        self.updated_at = datetime.now().isoformat()
        return h

    def record_attempt(self, tool_name: str, tool_args: dict, result_summary: str,
                       observation_matched: bool | None = None) -> None:
        self.attempts.append({
            "step": self.budgets["current_step"],
            "hypothesis_id": self.active_hypothesis_id,
            "tool": tool_name,
            "args": tool_args,
            "result_summary": result_summary[:500],
            "observation_matched": observation_matched,
            "at": datetime.now().isoformat(),
        })
        self.budgets["tool_calls"] += 1
        self.updated_at = datetime.now().isoformat()

    def check_stagnation_and_replan(self) -> bool:
        """
        Check if active hypothesis is stuck (3 consecutive steps without progress).
        If stuck, marks current hypothesis as abandoned/refuted and switches to next.
        Returns True if a replan occurred.
        """
        active = self.get_active_hypothesis()
        if not active:
            return False

        if active.stagnation_count >= 3:
            active.status = "abandoned"
            self.active_hypothesis_id = None
            next_h = self.get_active_hypothesis()
            if next_h:
                next_h.status = "testing"
                self.active_hypothesis_id = next_h.id
            self.status = "REPLAN"
            self.updated_at = datetime.now().isoformat()
            return True
        return False

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "root_id": self.root_id,
            "category": self.category,
            "goal": self.goal,
            "confirmed_facts": list(self.confirmed_facts),
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "active_hypothesis_id": self.active_hypothesis_id,
            "attempts": list(self.attempts),
            "artifacts": list(self.artifacts),
            "budgets": dict(self.budgets),
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SessionState":
        hyp_objs = [Hypothesis.from_dict(h) for h in data.get("hypotheses", [])]
        data_copy = dict(data)
        data_copy["hypotheses"] = hyp_objs
        return cls(**data_copy)
