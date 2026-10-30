"""CTF Helper v2.0 - Tool Safety, Sandbox & Lineage Budget Policy."""
from __future__ import annotations

from typing import Any
from ctf_checkpoint import CheckpointStore


class ToolPolicy:
    """Enforces boundaries, limits, and isolation on all tool executions."""

    def __init__(self, root_id: str, checkpoint_store: CheckpointStore | None = None):
        self.root_id = root_id
        self.store = checkpoint_store or CheckpointStore()

    def check_http_direct_allowed(self, current_session_used: int, limit: int = 8) -> tuple[bool, str]:
        lineage = self.store.get_lineage_budget(self.root_id)
        total_used = lineage.get("http_direct_used", 0) + current_session_used
        if total_used >= limit:
            return False, f"동일 문제 계보 전체의 직접 HTTP 요청 한도({limit}회)를 초과했습니다."
        return True, ""

    def check_http_batch_allowed(self, current_session_used: int, limit: int = 300) -> tuple[bool, str]:
        lineage = self.store.get_lineage_budget(self.root_id)
        total_used = lineage.get("http_batch_used", 0) + current_session_used
        if total_used >= limit:
            return False, f"동일 문제 계보 전체의 오라클 배치 HTTP 요청 한도({limit}회)를 초과했습니다."
        return True, ""

    def check_tcp_allowed(self, current_session_used: int, limit: int = 8) -> tuple[bool, str]:
        lineage = self.store.get_lineage_budget(self.root_id)
        total_used = lineage.get("tcp_used", 0) + current_session_used
        if total_used >= limit:
            return False, f"동일 문제 계보 전체의 TCP 요청 한도({limit}회)를 초과했습니다."
        return True, ""

    def validate_docker_sandbox(self, docker_enabled: bool) -> tuple[bool, str]:
        if not docker_enabled:
            return False, "Docker Python 격리 계산이 비활성화되어 있습니다. 설정에서 활성화하세요."
        return True, ""
