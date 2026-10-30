"""Optional AirLLM worker. Run in its own CUDA environment; no heavy imports in the web app."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ctf_airllm import AIRLLM_MODEL

HF_MODEL = "Qwen/Qwen3-14B"


def parse_output(text: str, tools: list[dict], thinking: bool = False) -> dict:
    """Parse Qwen's documented tool format, without evaluating generated Python."""
    text = text.strip().removesuffix("<|im_end|>").removesuffix("<|endoftext|>").strip()
    thought = ""
    if "</think>" in text:
        thought, text = text.split("</think>", 1)
        thought = thought.replace("<think>", "").strip()
    elif "<think>" in text or thinking:
        raise ValueError("추론이 출력 토큰 한도 안에 끝나지 않았습니다. Quick 모드 또는 --max-new-tokens 증가를 사용하세요.")
    allowed = {tool["function"]["name"] for tool in tools}
    calls = []
    for match in re.finditer(r"<tool_call>\s*(.*?)\s*</tool_call>", text, re.S):
        call = json.loads(match.group(1))
        name, args = call.get("name"), call.get("arguments", {})
        if isinstance(args, str):
            args = json.loads(args)
        if name not in allowed or not isinstance(args, dict):
            raise ValueError("모델이 지원되지 않는 도구 또는 잘못된 JSON 인수를 생성했습니다.")
        calls.append({"type": "function", "function": {"name": name, "arguments": args}})
    content = re.sub(r"<tool_call>.*?</tool_call>", "", text, flags=re.S).strip()
    if "<tool_call>" in content or "</tool_call>" in content:
        raise ValueError("도구 호출 JSON이 끝나기 전에 생성이 종료됐습니다. --max-new-tokens를 늘리세요.")
    return {"role": "assistant", "content": content, "thinking": thought, "tool_calls": calls}


def preflight(cache: Path) -> dict:
    cache.mkdir(parents=True, exist_ok=True)
    missing = [name for name in ("torch", "transformers", "airllm") if importlib.util.find_spec(name) is None]
    info = {"cache": str(cache.resolve()), "free_gib": round(shutil.disk_usage(cache).free / 2**30, 1),
            "missing_packages": missing, "cuda": False}
    if not missing:
        import torch
        info["cuda"] = torch.cuda.is_available()
        info["torch"] = torch.__version__
        if info["cuda"]:
            info["gpu"] = torch.cuda.get_device_name(0)
            info["vram_gib"] = round(torch.cuda.get_device_properties(0).total_memory / 2**30, 1)
            # Detect incompatible CUDA wheels before downloading any model weights.
            (torch.ones((8, 8), device="cuda") @ torch.ones((8, 8), device="cuda")).sum().item()
    return info


class Engine:
    def __init__(self, cache: Path, context: int = 8192, max_new_tokens: int = 512,
                 compression: str | None = None, delete_original: bool = False):
        self.cache = cache.resolve()
        self.context = context
        self.max_new_tokens = max_new_tokens
        self.compression = compression
        self.delete_original = delete_original
        self.model = None
        self.state = "idle"
        self.error = None
        self.lock = threading.Lock()
        self.last_tokens = 0
        self.last_seconds = 0.0

    def status(self) -> dict:
        return {"model": AIRLLM_MODEL, "hf_model": HF_MODEL, "ready": self.state in {"ready", "generating"},
                "state": self.state, "error": self.error, "context": self.context,
                "max_new_tokens": self.max_new_tokens, "cache": str(self.cache),
                "last_tokens": self.last_tokens, "last_seconds": round(self.last_seconds, 2)}

    def load(self):
        with self.lock:
            if self.model is not None:
                return
            self.state, self.error = "loading", None
            try:
                info = preflight(self.cache)
                if info["missing_packages"]:
                    raise RuntimeError("필요 패키지 없음: " + ", ".join(info["missing_packages"]))
                if not info["cuda"]:
                    raise RuntimeError("CUDA GPU를 사용할 수 없습니다. CUDA 12.8 이상을 지원하는 PyTorch 환경을 확인하세요.")
                # First split retains both ~28 GiB originals and layer shards. Leave OS headroom.
                if not (self.cache / "prepared.json").is_file() and info["free_gib"] < 70:
                    raise RuntimeError(f"첫 다운로드·변환에는 여유 공간 70GiB 이상이 필요합니다 (현재 {info['free_gib']}GiB). 다른 --cache 경로를 지정하세요.")
                os.environ["HF_HOME"] = str(self.cache / "huggingface")
                from airllm import AutoModel
                self.model = AutoModel.from_pretrained(
                    HF_MODEL, layer_shards_saving_path=str(self.cache / "layers"),
                    max_seq_len=self.context, compression=self.compression,
                    prefetching=False, delete_original=self.delete_original)
                (self.cache / "prepared.json").write_text(json.dumps({"model": HF_MODEL}), encoding="utf-8")
                self.state = "ready"
            except Exception as exc:
                self.state, self.error = "error", f"{type(exc).__name__}: {exc}"
                raise

    def chat(self, body: dict) -> dict:
        if body.get("model") != AIRLLM_MODEL:
            raise ValueError("이 서버는 airllm:qwen3-14b만 지원합니다.")
        if self.model is None:
            raise RuntimeError("모델이 준비되지 않았습니다. 서버를 --load 옵션으로 실행하고 /health를 확인하세요.")
        if not self.lock.acquire(blocking=False):
            raise RuntimeError("AirLLM이 다른 요청을 처리 중입니다. 중복 생성 요청은 실행하지 않았습니다.")
        try:
            import torch
            messages = body.get("messages")
            if not isinstance(messages, list) or not messages:
                raise ValueError("messages는 비어 있지 않은 배열이어야 합니다.")
            tools = body.get("tools") or []
            thinking = bool(body.get("think", False))
            tokenizer = self.model.tokenizer
            prompt = tokenizer.apply_chat_template(messages, tools=tools or None, tokenize=False,
                        add_generation_prompt=True, enable_thinking=thinking)
            inputs = tokenizer(prompt, return_tensors="pt", return_attention_mask=False,
                               add_special_tokens=False)
            input_ids = inputs["input_ids"]
            count = input_ids.shape[-1]
            wanted = int((body.get("options") or {}).get("num_predict", self.max_new_tokens))
            output_limit = min(max(1, wanted), self.max_new_tokens)
            if count + output_limit > self.context:
                raise ValueError(f"컨텍스트 한도 초과: 입력 {count} + 출력 {output_limit} > {self.context}. 입력을 줄이거나 --context를 늘리세요. 내용은 자동으로 잘라내지 않았습니다.")
            self.state = "generating"
            start = time.monotonic()
            with torch.inference_mode():
                output = self.model.generate(input_ids.to(self.model.device), max_new_tokens=output_limit,
                    do_sample=True, temperature=0.6 if thinking else 0.7,
                    top_p=0.95 if thinking else 0.8, top_k=20, use_cache=True,
                    return_dict_in_generate=True, pad_token_id=tokenizer.eos_token_id)
            tokens = output.sequences[0][count:]
            text = tokenizer.decode(tokens, skip_special_tokens=False)
            message = parse_output(text, tools, thinking)
            self.last_tokens, self.last_seconds = len(tokens), time.monotonic() - start
            return {"model": AIRLLM_MODEL, "message": message, "prompt_eval_count": count,
                    "eval_count": len(tokens), "done": True,
                    "done_reason": "length" if len(tokens) >= output_limit else "stop"}
        finally:
            self.state = "ready"
            self.lock.release()


def serve(engine: Engine, port: int, load: bool = False):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, code, body):
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def local(self):
            return self.headers.get("Host") in {f"127.0.0.1:{port}", f"localhost:{port}"}

        def do_GET(self):
            if not self.local():
                return self.reply(403, {"error": "로컬 요청만 허용합니다."})
            self.reply(200, engine.status()) if self.path == "/health" else self.reply(404, {"error": "경로 없음"})

        def do_POST(self):
            # Browser pages cannot drive the CUDA worker directly. The local app calls it server-side.
            if not self.local() or self.headers.get("Origin"):
                return self.reply(403, {"error": "로컬 서버 호출만 허용합니다."})
            if self.path != "/api/chat":
                return self.reply(404, {"error": "경로 없음"})
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 1 <= size <= 2 * 1024 * 1024:
                    raise ValueError("요청 크기는 2MiB 이하여야 합니다.")
                self.reply(200, engine.chat(json.loads(self.rfile.read(size))))
            except (ValueError, TypeError, KeyError) as exc:
                self.reply(422, {"error": str(exc)})
            except Exception as exc:
                self.reply(503, {"error": f"{type(exc).__name__}: {exc}"})

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    if load:
        def background_load():
            try:
                engine.load()
            except Exception as exc:
                print(f"AirLLM load failed: {exc}", flush=True)
        threading.Thread(target=background_load, daemon=True).start()
    print(f"AirLLM worker: http://127.0.0.1:{port} (health: /health)", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def main():
    parser = argparse.ArgumentParser(description="AirLLM Qwen3-14B local worker")
    parser.add_argument("--cache", type=Path, default=Path(__file__).resolve().parents[1] / ".runtime" / "airllm")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--context", type=int, default=8192)
    parser.add_argument("--max-new-tokens", type=int, default=512)
    parser.add_argument("--compression", choices=["4bit", "8bit"])
    parser.add_argument("--delete-original", action="store_true")
    parser.add_argument("--check", action="store_true", help="Check dependencies/CUDA/disk without downloading weights")
    parser.add_argument("--load", action="store_true", help="Download/split/load the model in the background")
    args = parser.parse_args()
    if not 128 <= args.context <= 32768 or not 1 <= args.max_new_tokens < args.context:
        parser.error("context는 128~32768, max-new-tokens는 context보다 작은 양수여야 합니다.")
    if args.check:
        info = preflight(args.cache)
        print(json.dumps(info, ensure_ascii=False, indent=2))
        return 0 if info["cuda"] and not info["missing_packages"] else 1
    serve(Engine(args.cache, args.context, args.max_new_tokens, args.compression, args.delete_original), args.port, args.load)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
