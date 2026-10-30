"""CTF Helper v2.0 - Candidate Verification & Provenance State Machine."""
from __future__ import annotations

from enum import Enum
import re


class VerificationState(str, Enum):
    MODEL_SUGGESTED = "MODEL_SUGGESTED"       # Guessed/suggested by model
    INPUT_OBSERVED = "INPUT_OBSERVED"         # Observed in user prompt / problem file
    TOOL_DERIVED = "TOOL_DERIVED"             # Extracted from local tool (decoders, python sandbox, archive, binary)
    REMOTE_OBSERVED = "REMOTE_OBSERVED"       # Received directly from CTF server (HTTP response, TCP output)
    REPRODUCED = "REPRODUCED"                 # Confirmed by executing saved reproduction script
    OFFICIALLY_VERIFIED = "OFFICIALLY_VERIFIED"  # Verified by official scoring API (Opt-in only)
    DECOY = "DECOY"                           # Marked as fake/dummy/decoy
    FRAGMENT = "FRAGMENT"                     # Incomplete piece or fragment
    REJECTED = "REJECTED"                     # Tested and found invalid


DECOY_KEYWORDS = re.compile(
    r"\b(?:fake|dummy|decoy|not\.real|mock|sample|placeholder|example)\b|가짜|미끼",
    re.IGNORECASE
)
FRAGMENT_KEYWORDS = re.compile(
    r"\b(?:fragment|piece|part)\b|조각|일부",
    re.IGNORECASE
)


def is_decoy_flag_value(flag: str) -> bool:
    """Inspect the flag content itself for obvious decoy strings like Fake_Flag."""
    inner = flag
    if "{" in flag and flag.endswith("}"):
        inner = flag.split("{", 1)[1][:-1]
    if re.search(r"(?:fake|dummy|decoy|sample)", inner, re.IGNORECASE):
        return True
    return False


def classify_flag(flag: str, content: str, source: str,
                  existing_role: str | None = None) -> tuple[VerificationState, str]:
    """
    Classify a flag observation with full provenance tracking.
    Returns (VerificationState, human_readable_status).
    """
    # 1. Check for decoy in the flag string itself
    if is_decoy_flag_value(flag):
        return VerificationState.DECOY, "미끼(Fake/Decoy) 플래그로 판별됨 (정답 아님)"

    # 2. Check surrounding context in the source content
    pos = content.find(flag)
    if pos >= 0:
        line_start = content.rfind("\n", 0, pos) + 1
        line_end = content.find("\n", pos)
        context = content[line_start:line_end if line_end >= 0 else pos + len(flag) + 80][:240]
    else:
        context = content[:240]

    if DECOY_KEYWORDS.search(context):
        return VerificationState.DECOY, "미끼(Fake/Decoy) 플래그로 판별됨 (정답 아님)"
    if FRAGMENT_KEYWORDS.search(context):
        return VerificationState.FRAGMENT, "플래그 조각/일부로 판별됨 (미완성)"

    # 3. Check existing role preservation
    if existing_role in {VerificationState.DECOY.value, "decoy"}:
        return VerificationState.DECOY, "미끼(Fake/Decoy) 플래그로 판별됨 (정답 아님)"
    if existing_role in {VerificationState.FRAGMENT.value, "fragment"}:
        return VerificationState.FRAGMENT, "플래그 조각/일부로 판별됨 (미완성)"
    if existing_role in {VerificationState.REJECTED.value, "rejected"}:
        return VerificationState.REJECTED, "검증 결과 오답으로 제외됨"

    # 4. Classify based on exact source provenance
    if source.startswith(("문제 웹 응답:", "문제 서버:", "웹 요청 응답:", "TCP 응답:")):
        return VerificationState.REMOTE_OBSERVED, "원격 문제 서버 응답에서 직접 수신됨 (유력 후보)"

    if source in {"디코딩 결과", "격리 Python 실행 출력"} or \
       source.startswith(("아카이브 내부", "해시 계산:", "바이너리 분석:")):
        return VerificationState.TOOL_DERIVED, "로컬 도구 실행/계산으로 도출됨 (미검증 후보)"

    if source.startswith("입력 파일:") or source in {"문제 설명", "추가 관찰"}:
        return VerificationState.INPUT_OBSERVED, "입력 데이터에서 관찰됨 (미검증 후보)"

    if source == "모델 답변" or source == "모델 추론":
        return VerificationState.MODEL_SUGGESTED, "모델 추론으로 제안됨 (정답 미확인)"

    return VerificationState.INPUT_OBSERVED, "관찰됨 (정답 미확인)"


class ObjectiveVerifier:
    """Verifies solve status and filters candidates based on formal evidence."""

    @staticmethod
    def is_actionable_candidate(record: dict) -> bool:
        """Returns True if the record is a candidate and NOT a decoy, fragment, or rejected."""
        role = record.get("role", "candidate")
        if role in {"decoy", "fragment", "rejected",
                    VerificationState.DECOY.value,
                    VerificationState.FRAGMENT.value,
                    VerificationState.REJECTED.value}:
            return False
        return True

    @staticmethod
    def evaluate_candidates(evidence_list: list[dict]) -> dict:
        """
        Group and evaluate candidates cleanly.
        Returns:
            {
                "remote_flags": list[str],
                "tool_derived_flags": list[str],
                "input_flags": list[str],
                "model_suggested_flags": list[str],
                "decoy_flags": list[str],
                "valid_candidates": list[dict],
                "result_status": str ("remote_observed" | "tool_derived" | "candidate_only" | "unresolved")
            }
        """
        valid = [item for item in evidence_list if ObjectiveVerifier.is_actionable_candidate(item)]
        decoys = [item["flag"] for item in evidence_list if not ObjectiveVerifier.is_actionable_candidate(item)]

        remote_flags = list(dict.fromkeys(
            item["flag"] for item in valid
            if item.get("source", "").startswith(("문제 웹 응답:", "문제 서버:", "웹 요청 응답:", "TCP 응답:"))
            or item.get("status_code") == VerificationState.REMOTE_OBSERVED.value
        ))

        tool_flags = list(dict.fromkeys(
            item["flag"] for item in valid
            if (item.get("source") in {"디코딩 결과", "격리 Python 실행 출력"} or
                item.get("source", "").startswith(("아카이브 내부", "해시 계산:", "바이너리 분석:")))
            and item["flag"] not in remote_flags
        ))

        other_flags = list(dict.fromkeys(
            item["flag"] for item in valid
            if item["flag"] not in remote_flags and item["flag"] not in tool_flags
        ))

        if remote_flags:
            status = "remote_observed"
        elif tool_flags:
            status = "tool_derived"
        elif other_flags:
            status = "candidate_only"
        else:
            status = "unresolved"

        return {
            "remote_flags": remote_flags,
            "tool_derived_flags": tool_flags,
            "other_flags": other_flags,
            "decoy_flags": list(dict.fromkeys(decoys)),
            "valid_candidates": valid,
            "result_status": status,
        }
