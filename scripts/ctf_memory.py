"""CTF Helper v2.0 - Evidence Preserving Memory & Turn-Boundary Compaction."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
import hashlib
import json
import uuid


@dataclass
class EvidenceRecord:
    evidence_id: str
    source_type: str
    file_path_or_tool: str
    content: str
    sha256: str
    observed_at: str = field(default_factory=lambda: datetime.now().isoformat())
    untrusted: bool = True
    flag: str | None = None
    role: str = "candidate"  # candidate, decoy, fragment, rejected
    status: str = "미검증"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "EvidenceRecord":
        return cls(**d)


class MemoryManager:
    """
    Manages multi-turn conversation memory, preserves atomic evidence pointers,
    and handles turn-boundary compaction without hallucinated flag pollution.
    """

    def __init__(self, max_context_tokens: int = 16384, compaction_token_threshold: int = 11500):
        self.max_context_tokens = max_context_tokens
        self.compaction_token_threshold = compaction_token_threshold
        self.evidence_store: dict[str, EvidenceRecord] = {}
        self.summaries: list[dict] = []

    def record_evidence(self, source_type: str, file_path_or_tool: str,
                        content: str, flag: str | None = None,
                        role: str = "candidate", status: str = "미검증",
                        untrusted: bool = True) -> EvidenceRecord:
        content_bytes = content.encode("utf-8", errors="replace")
        sha256 = hashlib.sha256(content_bytes).hexdigest()
        e_id = f"ev_{len(self.evidence_store) + 1}_{sha256[:8]}"

        record = EvidenceRecord(
            evidence_id=e_id,
            source_type=source_type,
            file_path_or_tool=file_path_or_tool,
            content=content[:5000],
            sha256=sha256,
            untrusted=untrusted,
            flag=flag,
            role=role,
            status=status
        )
        self.evidence_store[e_id] = record
        return record

    def should_compact(self, current_chars: int, prompt_eval_count: int) -> bool:
        """Determines if compaction should occur at the end of the current turn."""
        return current_chars >= 26000 or prompt_eval_count >= self.compaction_token_threshold

    def create_compact_user_message(self, description: str, service_output: str,
                                    file_list: str, summary_text: str,
                                    active_evidence: list[dict]) -> str:
        """
        Constructs the post-compaction user message.
        Does NOT elevate the summary text to genuine evidence.
        """
        # Save summary in history as unverified
        self.summaries.append({
            "summary": summary_text,
            "created_at": datetime.now().isoformat(),
            "unverified": True
        })

        evidence_lines = []
        for item in active_evidence:
            if item.get("role") not in {"decoy", "fragment", "rejected"}:
                evidence_lines.append(f"- {item.get('flag')} ({item.get('source')})")

        evidence_section = "\n".join(evidence_lines)

        return (
            f"문제 설명:\n{description}\n\n"
            f"문제 서버 출력:\n{service_output or '제공되지 않음'}\n\n"
            f"입력 파일:\n{file_list}\n\n"
            f"--- [이전 분석 단계의 핵심 진행 상황 및 단서 압축 요약 (검증되지 않은 모델 메모리)] ---\n"
            f"{summary_text}\n\n"
            + (f"현재까지 기록된 유효 Flag 후보:\n{evidence_section}\n\n" if evidence_section else "")
            + "위의 핵심 단서와 이전 진행 상황을 바탕으로, 중복 시도를 피하고 아직 풀리지 않은 부분을 끝까지 추적하여 Flag를 찾으세요."
        )
