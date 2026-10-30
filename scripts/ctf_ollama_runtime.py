"""CTF Helper v2.0 - Centralized Ollama Inference Runtime."""
from __future__ import annotations

import json
import os
import re
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

OLLAMA_BASE_URL = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
if not OLLAMA_BASE_URL.startswith("http://") and not OLLAMA_BASE_URL.startswith("https://"):
    OLLAMA_BASE_URL = f"http://{OLLAMA_BASE_URL}"

# Default parameters per mode
MODE_CONFIGS = {
    "quick": {
        "think": False,
        "options": {
            "temperature": 0.0,
            "num_ctx": 16384,
            "num_predict": 2048,
        }
    },
    "deep": {
        "think": True,
        "options": {
            "temperature": 0.6,
            "top_p": 0.95,
            "top_k": 20,
            "num_ctx": 16384,
            "num_predict": 4096,
        }
    },
    "compact": {
        "think": False,
        "options": {
            "temperature": 0.0,
            "num_ctx": 16384,
            "num_predict": 2048,
        }
    },
}


def ollama_raw_request(endpoint: str, payload: dict | None = None, timeout: int = 180) -> dict:
    url = f"{OLLAMA_BASE_URL}{endpoint}"
    data = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = Request(url, data=data, headers={"Content-Type": "application/json"} if data else {})
    try:
        with urlopen(req, timeout=timeout) as resp:
            return json.load(resp)
    except (HTTPError, URLError, TimeoutError) as exc:
        raise RuntimeError(f"Ollama 호출 실패 ({url}): {exc}") from exc


def repair_json_argument(arg_str: str) -> dict | None:
    """Attempt 1 lightweight repair for malformed JSON tool call arguments."""
    arg_str = arg_str.strip()
    if not arg_str:
        return {}
    try:
        parsed = json.loads(arg_str)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    # Try simple fixes: replace trailing comma, fix single quotes
    cleaned = re.sub(r",\s*([\]}])", r"\1", arg_str)
    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    # If single quotes were used for JSON keys/strings
    if "'" in cleaned and '"' not in cleaned:
        double_quoted = cleaned.replace("'", '"')
        try:
            parsed = json.loads(double_quoted)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass

    return None


class OllamaRuntime:
    """Robust unified runtime for Ollama Qwen3 8B with Quick and Deep modes."""

    def __init__(self, base_url: str = OLLAMA_BASE_URL):
        self.base_url = base_url

    def check_model(self, model: str) -> None:
        tags = ollama_raw_request("/api/tags", timeout=5).get("models", [])
        available = [item.get("name") for item in tags if item.get("name")]
        if model not in available:
            raise RuntimeError(
                f"Ollama에 {model} 모델이 없습니다. ollama pull {model}을 실행하세요. 사용 가능: " +
                ", ".join(available)
            )

    def chat(self, model: str, messages: list[dict], tools: list[dict] | None = None,
             mode: str = "quick", config_override: dict | None = None,
             timeout: int = 180) -> dict:
        base_cfg = MODE_CONFIGS.get(mode, MODE_CONFIGS["quick"]).copy()
        options = dict(base_cfg["options"])
        think = base_cfg["think"]

        if config_override:
            if "think" in config_override:
                think = bool(config_override["think"])
            if "options" in config_override:
                options.update(config_override["options"])

        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            "think": think,
            "options": options,
        }
        if tools:
            payload["tools"] = tools

        start = time.monotonic()
        raw = ollama_raw_request("/api/chat", payload, timeout=timeout)
        duration = time.monotonic() - start

        msg = raw.get("message", {})
        raw_content = msg.get("content", "") or ""
        tool_calls = msg.get("tool_calls") or []

        # Parse thinking tags if present in raw_content
        thinking = ""
        content = raw_content
        think_match = re.search(r"<think>(.*?)</think>", raw_content, flags=re.DOTALL)
        if think_match:
            thinking = think_match.group(1).strip()
            content = re.sub(r"<think>.*?</think>", "", raw_content, flags=re.DOTALL).strip()

        # Validate and sanitize tool calls
        sanitized_calls = []
        for call in tool_calls:
            fn = call.get("function", {})
            name = fn.get("name")
            if not name:
                continue
            args = fn.get("arguments", {})
            if isinstance(args, str):
                fixed = repair_json_argument(args)
                args = fixed if fixed is not None else {}
            elif not isinstance(args, dict):
                args = {}
            sanitized_calls.append({
                "type": call.get("type", "function"),
                "function": {
                    "name": str(name),
                    "arguments": args,
                }
            })

        return {
            "content": content,
            "thinking": thinking,
            "tool_calls": sanitized_calls,
            "prompt_eval_count": raw.get("prompt_eval_count") or 0,
            "eval_count": raw.get("eval_count") or 0,
            "duration_seconds": round(duration, 3),
            "raw_response": raw,
        }
