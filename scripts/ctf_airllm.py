"""Small standard-library client for the optional, isolated AirLLM worker."""
from __future__ import annotations

import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import urlsplit

AIRLLM_MODEL = "airllm:qwen3-14b"


def base_url() -> str:
    value = os.environ.get("CTF_AIRLLM_URL", "http://127.0.0.1:8766").rstrip("/")
    parsed = urlsplit(value)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"} or parsed.path or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("AirLLM 주소는 로컬 HTTP 주소여야 합니다 (예: http://127.0.0.1:8766).")
    return value


def request(path: str, payload: dict | None = None, timeout: int = 3) -> dict:
    data = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = Request(base_url() + path, data=data, headers={"Content-Type": "application/json"})
    try:
        with urlopen(req, timeout=timeout) as response:
            return json.load(response)
    except HTTPError as exc:
        try:
            message = json.loads(exc.read()).get("error", str(exc.code))
        except (ValueError, OSError):
            message = str(exc.code)
        raise RuntimeError(f"AirLLM: {message}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError("AirLLM 서버에 연결하지 못했습니다. scripts/start_airllm.ps1 또는 Linux 실행 명령을 확인하세요. 느린 생성 중 연결이 끊겼다면 서버 상태를 먼저 확인하세요.") from exc


def health() -> dict:
    try:
        result = request("/health")
        if not isinstance(result, dict) or result.get("model") != AIRLLM_MODEL:
            raise ValueError("AirLLM 서버의 모델 식별자가 일치하지 않습니다.")
        return result
    except (RuntimeError, ValueError) as exc:
        return {"ready": False, "model": AIRLLM_MODEL, "state": "offline", "error": str(exc)}


def check_model() -> dict:
    result = health()
    if not result.get("ready"):
        raise RuntimeError("AirLLM Qwen3-14B 준비 필요: " + str(result.get("error") or result.get("state")))
    return result


def chat(payload: dict) -> dict:
    # Layer streaming can take minutes per turn. Never silently fall back to 8B/API.
    timeout = max(60, min(86400, int(os.environ.get("CTF_AIRLLM_TIMEOUT", "14400"))))
    result = request("/api/chat", payload, timeout=timeout)
    if not isinstance(result, dict) or result.get("model") != AIRLLM_MODEL or not isinstance(result.get("message"), dict):
        raise RuntimeError("AirLLM 서버가 잘못된 모델 ID 또는 응답 형식을 반환했습니다.")
    return result
