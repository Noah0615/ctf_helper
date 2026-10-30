"""CTF Helper v2.0 - Agent Controller and Replanning Loop."""
from __future__ import annotations

from typing import Callable
from ctf_agent_state import Hypothesis, SessionState
from ctf_verifier import ObjectiveVerifier, VerificationState


class AgentController:
    """
    Coordinates hypothesis generation, single-action execution, progress evaluation,
    and automatic replanning when stagnation occurs.
    """

    def __init__(self, state: SessionState, event_callback: Callable[[str], None] | None = None):
        self.state = state
        self.event = event_callback or (lambda msg: None)

    def initialize_plan(self, initial_hypotheses: list[dict] | None = None) -> None:
        """Seed initial hypotheses if provided, otherwise create default exploratory hypothesis."""
        self.state.status = "PLAN"
        if initial_hypotheses:
            for item in initial_hypotheses[:3]:
                self.state.add_hypothesis(
                    title=item.get("title", "초기 가설"),
                    reason=item.get("reason", "초기 문제 분석"),
                    expected_observation=item.get("expected_observation", "단서 또는 플래그 발견"),
                    next_tool=item.get("next_tool", "list_files")
                )
        else:
            self.state.add_hypothesis(
                title="파일 구조 및 서비스 상태 정적 조사",
                reason="주어진 문제 파일의 형식, 취약점 패턴 및 초기 입력을 확인하기 위함",
                expected_observation="핵심 실행 파일, 암호화된 텍스트 또는 통신 경로 파악",
                next_tool="list_files"
            )
        active = self.state.get_active_hypothesis()
        if active:
            active.status = "testing"

    def evaluate_step_progress(self, tool_name: str, tool_result: str,
                               prev_evidence_count: int,
                               current_evidence: list[dict]) -> tuple[bool, str]:
        """
        Evaluate if the step made genuine progress.
        Progress is defined by:
        1. New non-decoy evidence or candidate was found.
        2. Expected pattern matched in tool_result.
        3. A hypothesis was confirmed or refuted.
        """
        active = self.state.get_active_hypothesis()
        if not active:
            return False, "활성 가설 없음"

        # Check for new non-decoy candidate
        new_evidence_count = len(current_evidence) - prev_evidence_count
        new_valid = [
            item for item in current_evidence[prev_evidence_count:]
            if ObjectiveVerifier.is_actionable_candidate(item)
        ]

        # Check tool result content
        is_error = "오류" in tool_result[:100] or "실패" in tool_result[:100] or not tool_result.strip()

        if new_valid:
            active.stagnation_count = 0
            return True, f"새로운 유효 단서/후보 {len(new_valid)}건 발견"

        if not is_error and len(tool_result.strip()) > 30:
            # Meaningful tool output was produced
            active.stagnation_count = max(0, active.stagnation_count - 1)
            return True, "유의미한 도구 출력 획득"

        active.stagnation_count += 1
        return False, f"진척 없음 (정체 카운트: {active.stagnation_count}/3)"

    def handle_turn_completion(self, current_evidence: list[dict], has_tools: bool) -> tuple[str, bool]:
        """
        Assess state at the end of a turn.
        Returns (action_to_take, should_terminate):
        - ("SOLVED", True)
        - ("REPLAN", False)
        - ("CONTINUE", False)
        - ("BUDGET_EXHAUSTED", True)
        - ("UNRESOLVED", True)
        """
        eval_result = ObjectiveVerifier.evaluate_candidates(current_evidence)

        # 1. Check for genuine solve (remote observed or verified)
        if eval_result["remote_flags"]:
            self.state.status = "SOLVED"
            self.event(f"원격 검증된 플래그 확인: {eval_result['remote_flags'][0]}")
            return "SOLVED", True

        # 2. Check budget limits
        if self.state.budgets["current_step"] >= self.state.budgets["max_steps"]:
            self.state.status = "BUDGET_EXHAUSTED"
            return "BUDGET_EXHAUSTED", True

        # 3. Check for stagnation & trigger replan if needed
        if self.state.check_stagnation_and_replan():
            self.event("가설 정체 감지 (3회 연속 진척 없음) -> 대안 가설로 자동 전환 및 재계획")
            return "REPLAN", False

        # 4. If assistant provided no tools and only decoy/fake flags exist, do NOT terminate
        active = self.state.get_active_hypothesis()
        if not has_tools:
            if not active or all(h.status in {"refuted", "abandoned"} for h in self.state.hypotheses):
                # All hypotheses exhausted
                self.state.status = "UNRESOLVED"
                return "UNRESOLVED", True
            return "DEEP_DIVE", False

        return "CONTINUE", False
