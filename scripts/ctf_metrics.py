"""CTF Helper v2.0 - Execution & Hardware Metrics Collector."""
from __future__ import annotations

from datetime import datetime
import json
import os
import shutil
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def probe_ollama_metadata(model: str, ollama_url: str = "http://127.0.0.1:11434") -> dict:
    """Probe Ollama version and model digest/details without heavy inference."""
    version = "unknown"
    digest = "unknown"
    details: dict = {}
    try:
        req = Request(f"{ollama_url}/api/version", headers={"Content-Type": "application/json"})
        with urlopen(req, timeout=3) as resp:
            version = json.load(resp).get("version", "unknown")
    except Exception:
        pass

    try:
        req = Request(f"{ollama_url}/api/show", data=json.dumps({"model": model}).encode("utf-8"),
                      headers={"Content-Type": "application/json"})
        with urlopen(req, timeout=5) as resp:
            show_data = json.load(resp)
            details = show_data.get("details", {})
            digest = show_data.get("digest") or details.get("digest") or "unknown"
    except Exception:
        # Fallback to /api/tags
        try:
            req = Request(f"{ollama_url}/api/tags", headers={"Content-Type": "application/json"})
            with urlopen(req, timeout=5) as resp:
                tags = json.load(resp).get("models", [])
                for item in tags:
                    if item.get("name") == model or item.get("model") == model:
                        digest = item.get("digest", "unknown")
                        details = item.get("details", {})
                        break
        except Exception:
            pass

    return {
        "ollama_version": version,
        "model_digest": digest,
        "model_details": details,
    }


def probe_gpu_info() -> dict:
    """Collect GPU / accelerator information safely without raising exceptions."""
    info = {"name": "CPU/Unknown", "total_vram_mb": 0, "available_vram_mb": 0, "driver": ""}
    # 1. Try nvidia-smi if available
    nvidia_smi = shutil.which("nvidia-smi")
    if nvidia_smi:
        try:
            cmd = [
                nvidia_smi,
                "--query-gpu=name,memory.total,memory.free,driver_version",
                "--format=csv,noheader,nounits"
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3, check=False)
            if proc.returncode == 0 and proc.stdout.strip():
                line = proc.stdout.strip().splitlines()[0]
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 4:
                    info["name"] = parts[0]
                    info["total_vram_mb"] = int(float(parts[1]))
                    info["available_vram_mb"] = int(float(parts[2]))
                    info["driver"] = parts[3]
                    return info
        except Exception:
            pass
    return info


class CTFMetrics:
    """Tracks latency, token counts, tool execution rates, and compactions for a CTF case."""

    def __init__(self, run_id: str, model_name: str, options: dict | None = None):
        self.run_id = run_id
        self.model_name = model_name
        self.options = options or {}
        self.start_timestamp = datetime.now().isoformat()
        self._start_time = time.monotonic()
        self.end_timestamp: str | None = None
        self.elapsed_seconds: float = 0.0

        # Hardware & Model metadata
        meta = probe_ollama_metadata(model_name)
        self.ollama_version = meta["ollama_version"]
        self.model_digest = meta["model_digest"]
        self.model_details = meta["model_details"]
        self.gpu_info = probe_gpu_info()

        # Token & Turn tracking
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.total_tokens = 0
        self.turns_count = 0
        self.total_inference_latency = 0.0

        # Tool tracking
        self.tool_calls_count = 0
        self.tool_failures_count = 0
        self.tool_calls_breakdown: dict[str, int] = {}

        # Architecture & Flow tracking
        self.compactions_count = 0
        self.stagnation_count = 0
        self.replan_count = 0

    def record_turn(self, prompt_tokens: int, eval_tokens: int, latency_seconds: float = 0.0) -> None:
        self.turns_count += 1
        self.prompt_tokens += max(0, prompt_tokens)
        self.completion_tokens += max(0, eval_tokens)
        self.total_tokens = self.prompt_tokens + self.completion_tokens
        self.total_inference_latency += max(0.0, latency_seconds)

    def record_tool_call(self, tool_name: str, success: bool = True) -> None:
        self.tool_calls_count += 1
        self.tool_calls_breakdown[tool_name] = self.tool_calls_breakdown.get(tool_name, 0) + 1
        if not success:
            self.tool_failures_count += 1

    def record_compaction(self) -> None:
        self.compactions_count += 1

    def record_stagnation(self) -> None:
        self.stagnation_count += 1

    def record_replan(self) -> None:
        self.replan_count += 1

    def finish(self) -> dict:
        self.elapsed_seconds = round(time.monotonic() - self._start_time, 3)
        self.end_timestamp = datetime.now().isoformat()
        return self.to_dict()

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "model_name": self.model_name,
            "model_digest": self.model_digest,
            "ollama_version": self.ollama_version,
            "gpu_info": self.gpu_info,
            "options": self.options,
            "start_time": self.start_timestamp,
            "end_time": self.end_timestamp,
            "elapsed_seconds": self.elapsed_seconds,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "turns_count": self.turns_count,
            "total_inference_latency": round(self.total_inference_latency, 3),
            "tool_calls_count": self.tool_calls_count,
            "tool_failures_count": self.tool_failures_count,
            "tool_calls_breakdown": self.tool_calls_breakdown,
            "compactions_count": self.compactions_count,
            "stagnation_count": self.stagnation_count,
            "replan_count": self.replan_count,
        }
