"""Comprehensive unit tests for CTF Helper v2.0 Architecture & Modules."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from ctf_verifier import (
    VerificationState, is_decoy_flag_value, classify_flag, ObjectiveVerifier
)
from ctf_ollama_runtime import repair_json_argument, OllamaRuntime
from ctf_agent_state import Hypothesis, SessionState
from ctf_agent_controller import AgentController
from ctf_checkpoint import CheckpointStore
from ctf_tool_policy import ToolPolicy
from ctf_metrics import CTFMetrics
import ctf_helper as helper


class HelperV2Tests(unittest.TestCase):

    def test_1_decoy_flag_value_detection(self):
        """Test detection of decoy / fake flags in value or context."""
        self.assertTrue(is_decoy_flag_value("DH{**Fake_Flag**}"))
        self.assertTrue(is_decoy_flag_value("FLAG{this_is_dummy_flag}"))
        self.assertTrue(is_decoy_flag_value("ACDC{sample_decoy_flag}"))
        self.assertFalse(is_decoy_flag_value("DH{genuine_secret_key_1337}"))

        state, status = classify_flag("DH{**Fake_Flag**}", "Fake flag in file", "입력 파일: flag")
        self.assertEqual(state, VerificationState.DECOY)

        state2, _ = classify_flag("DH{secret}", "Note: this is a dummy flag for testing", "입력 파일: test.txt")
        self.assertEqual(state2, VerificationState.DECOY)

    def test_2_compaction_summary_does_not_pollute_evidence(self):
        """Test that hallucinated flags in compaction summary are NOT added to self.evidence."""
        case = helper.Case("Compaction test problem", [])
        system_content = "You are a CTF assistant."
        messages = [
            {"role": "system", "content": system_content},
            {"role": "user", "content": "Some context"}
        ]
        # Summary contains a hallucinated flag
        fake_summary = (
            "1. [확인된 핵심 단서]: RSA n, e 발견\n"
            "2. [실패한 시도]: 소인수분해 실패\n"
            "3. [발견된 Flag 후보]: DH{hallucinated_by_llm_summary}\n"
            "4. [다음 분석 계획]: 위너 공격 시도"
        )
        with patch.object(helper, "ollama_request", return_value={"message": {"content": fake_summary}}):
            compacted = case._compact_messages(helper.DEFAULT_MODEL, system_content, messages)

        # Check evidence: DH{hallucinated_by_llm_summary} must NOT be in evidence
        evidence_flags = [item["flag"] for item in case.evidence]
        self.assertNotIn("DH{hallucinated_by_llm_summary}", evidence_flags)
        self.assertIn("RSA n, e", compacted[1]["content"])

    def test_3_model_without_tools_does_not_claim_solved_on_unverified_flag(self):
        """Model giving an answer without tool calls does not stop if flag is fake or unverified."""
        case = helper.Case("Fake flag problem", [("chall.c", b"int main() {}")], flag_regex="DH{...}")
        # Case has only a decoy flag
        case.evidence = [{"flag": "DH{**Fake_Flag**}", "source": "입력 파일", "role": "decoy", "status": "미끼"}]
        self.assertFalse(case.has_derived_candidate())

    def test_4_turn_boundary_compaction_flag(self):
        """Compaction threshold sets needs_compaction for turn boundary execution."""
        case = helper.Case("Compaction timing test", [])
        self.assertFalse(case.memory.should_compact(current_chars=5000, prompt_eval_count=2000))
        self.assertTrue(case.memory.should_compact(current_chars=30000, prompt_eval_count=2000))
        self.assertTrue(case.memory.should_compact(current_chars=5000, prompt_eval_count=12000))

    def test_5_sqlite_checkpoint_save_and_load(self):
        """Verify lossless state and evidence persistence in SQLite checkpoint store."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_sessions.sqlite3"
            store = CheckpointStore(db_path)

            state = SessionState(run_id="run_12345678", root_id="run_12345678", category="pwn")
            state.add_hypothesis("ROP 체인 구성", "NX 활성화 확인", "system 호출", "disassemble_function")
            evidence = [
                {"flag": "DH{test_candidate}", "source": "디코딩 결과", "role": "candidate", "status": "도출됨"}
            ]

            store.save_session(state, evidence)

            loaded_state, loaded_evidence = store.load_session("run_12345678")
            self.assertIsNotNone(loaded_state)
            self.assertEqual(loaded_state.run_id, "run_12345678")
            self.assertEqual(loaded_state.category, "pwn")
            self.assertEqual(len(loaded_state.hypotheses), 1)
            self.assertEqual(loaded_state.hypotheses[0].title, "ROP 체인 구성")
            self.assertEqual(len(loaded_evidence), 1)
            self.assertEqual(loaded_evidence[0]["flag"], "DH{test_candidate}")

    def test_6_stagnation_replanning_loop(self):
        """Verify that 3 steps of stagnation trigger hypothesis replan."""
        state = SessionState(run_id="run_stag", root_id="run_stag")
        h1 = state.add_hypothesis("가설 1", "이유 1", "예상 1", "tool_1")
        h2 = state.add_hypothesis("가설 2", "이유 2", "예상 2", "tool_2")
        controller = AgentController(state)

        # 3 failures on active hypothesis
        for _ in range(3):
            controller.evaluate_step_progress("tool_1", "오류 발생", 0, [])

        self.assertEqual(h1.stagnation_count, 3)
        replan_triggered = state.check_stagnation_and_replan()
        self.assertTrue(replan_triggered)
        self.assertEqual(h1.status, "abandoned")
        self.assertEqual(state.active_hypothesis_id, h2.id)
        self.assertEqual(h2.status, "testing")

    def test_7_budget_exhaustion_detection(self):
        """Verify BUDGET_EXHAUSTED status when step count reaches maximum."""
        state = SessionState(run_id="run_budget", root_id="run_budget")
        state.budgets["max_steps"] = 5
        state.budgets["current_step"] = 5
        controller = AgentController(state)

        action, should_terminate = controller.handle_turn_completion([], has_tools=True)
        self.assertTrue(should_terminate)
        self.assertEqual(action, "BUDGET_EXHAUSTED")
        self.assertEqual(state.status, "BUDGET_EXHAUSTED")

    def test_8_lineage_budget_across_root_id(self):
        """Verify that lineage budget limits persist across multiple runs under same root_id."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_budgets.sqlite3"
            store = CheckpointStore(db_path)
            policy = ToolPolicy("root_ctf_001", store)

            # Record 6 direct HTTP requests
            store.update_lineage_budget("root_ctf_001", http_direct_delta=6)

            # In new session with 2 requests used -> total 8 -> at limit
            allowed, msg = policy.check_http_direct_allowed(current_session_used=2, limit=8)
            self.assertFalse(allowed)
            self.assertIn("계보 전체의 직접 HTTP 요청 한도", msg)

            # Within limit
            allowed, _ = policy.check_http_direct_allowed(current_session_used=1, limit=8)
            self.assertTrue(allowed)

    def test_9_repair_json_argument(self):
        """Verify repair of single quotes and trailing commas in tool call arguments."""
        # Clean json
        self.assertEqual(repair_json_argument('{"key": "value"}'), {"key": "value"})
        # Single quotes
        self.assertEqual(repair_json_argument("{'name': 'test.txt'}"), {"name": "test.txt"})
        # Trailing comma
        self.assertEqual(repair_json_argument('{"cmd": "ls",}'), {"cmd": "ls"})
        # Empty string
        self.assertEqual(repair_json_argument(""), {})

    def test_10_objective_verifier_classifications(self):
        """Verify candidate grouping and that decoys do not elevate to solved."""
        evidence = [
            {"flag": "DH{**Fake_Flag**}", "source": "입력 파일", "role": "decoy", "status": "미끼"},
            {"flag": "DH{genuine_flag_123}", "source": "문제 서버: http", "role": "candidate", "status": "원격 관찰"},
        ]
        res = ObjectiveVerifier.evaluate_candidates(evidence)
        self.assertEqual(res["remote_flags"], ["DH{genuine_flag_123}"])
        self.assertEqual(res["decoy_flags"], ["DH{**Fake_Flag**}"])
        self.assertEqual(res["result_status"], "remote_observed")


if __name__ == "__main__":
    unittest.main()
