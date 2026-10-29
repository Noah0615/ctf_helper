"""Loopback-only browser UI for ctf_helper.py (standard library only)."""
from __future__ import annotations

import base64
import binascii
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
import webbrowser

from ctf_helper import Case, RESULTS, DEFAULT_FLAG_REGEX, DEFAULT_MODEL, OPENAI_MODELS, CHALLENGE_CATEGORIES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, check_model
from ctf_openai import key_present, get_budget_summary

HOST, PORT = "127.0.0.1", 8765
PAGE = Path(__file__).with_name("ctf_helper.html").read_bytes()
JOBS: dict[str, dict] = {}
LOCK = threading.Lock()
RUN_LOCK = threading.Lock()  # One local model run at a time.


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Avoid logging challenge data or browser paths.

    def _reply(self, status: int, payload: dict | bytes, content_type="application/json"):
        data = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type + ("; charset=utf-8" if content_type.startswith("text/") else ""))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(data)

    def _local_request(self) -> bool:
        return self.headers.get("Host") in {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}

    def do_GET(self):
        if not self._local_request():
            return self._reply(403, {"error": "로컬 호스트 요청만 허용됩니다."})
        if self.path == "/":
            return self._reply(200, Path(__file__).with_name("ctf_helper.html").read_bytes(), "text/html")
        if self.path == "/app.js":
            return self._reply(200, Path(__file__).with_name("ctf_helper.js").read_bytes(), "text/javascript")
        if self.path == "/api/health":
            ollama_ready = True
            ollama_error = None
            try:
                check_model(DEFAULT_MODEL)
            except Exception as exc:
                ollama_ready = False
                ollama_error = str(exc)

            has_key = key_present()
            budget = get_budget_summary() if has_key else {
                "total_spent_usd": 0.0, "total_limit_usd": 30.0, "run_limit_usd": 2.0, "remaining_usd": 30.0
            }
            return self._reply(200, {
                "ready": ollama_ready or has_key,
                "ollama": {
                    "ready": ollama_ready,
                    "model": DEFAULT_MODEL,
                    "error": ollama_error,
                },
                "openai": {
                    "ready": has_key,
                    "models": list(OPENAI_MODELS),
                    "spent": budget["total_spent_usd"],
                    "limit": budget["total_limit_usd"],
                    "remaining": budget["remaining_usd"],
                    "run_limit": budget["run_limit_usd"],
                }
            })
        if self.path == "/api/history":
            history = []
            if RESULTS.is_dir():
                for folder in sorted(RESULTS.iterdir(), reverse=True)[:25]:
                    res_file = folder / "result.json"
                    if res_file.is_file():
                        try:
                            data = json.loads(res_file.read_text(encoding="utf-8"))
                            prob_file = folder / "problem.txt"
                            prob_text = prob_file.read_text(encoding="utf-8")[:100] if prob_file.is_file() else ""
                            history.append({
                                "id": data.get("run_id", folder.name),
                                "time": folder.name[:15],
                                "model": data.get("model", ""),
                                "flags": [item["flag"] for item in data.get("flag_candidates", [])],
                                "preview": prob_text.strip(),
                                "cost_usd": data.get("cost_usd"),
                            })
                        except Exception:
                            continue
            return self._reply(200, history)
        if self.path.startswith("/api/job/"):
            job_id = self.path.removeprefix("/api/job/")
            with LOCK:
                job = JOBS.get(job_id)
                snapshot = None if job is None else {**job, "events": list(job["events"])}
            if not snapshot:
                saved = RESULTS / job_id / "result.json"
                if saved.is_file():
                    try:
                        res = json.loads(saved.read_text(encoding="utf-8"))
                        snapshot = {"status": "done", "events": ["저장된 분석 결과 불러옴"], "result": res, "error": None}
                    except Exception:
                        pass
            return self._reply(200, snapshot) if snapshot else self._reply(404, {"error": "실행 기록 없음"})
        return self._reply(404, {"error": "경로 없음"})

    def do_POST(self):
        if self.path != "/api/solve" or not self._local_request():
            return self._reply(404, {"error": "경로 없음"})
        if self.headers.get("Origin") not in {f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}"}:
            return self._reply(403, {"error": "로컬 화면에서만 제출하세요."})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= 17 * 1024 * 1024:
                raise ValueError("요청 크기가 너무 큽니다.")
            body = json.loads(self.rfile.read(length))
            encoded = body.get("files", [])
            if not isinstance(encoded, list) or len(encoded) > 20:
                raise ValueError("파일은 최대 20개까지 선택하세요.")
            files = []
            size = 0
            for item in encoded:
                raw = base64.b64decode(item["data"], validate=True)
                if len(raw) > MAX_FILE_BYTES:
                    raise ValueError("파일 하나가 8 MiB를 초과했습니다.")
                size += len(raw)
                files.append((item["name"], raw))
            if size > MAX_TOTAL_BYTES:
                raise ValueError("파일 합계가 12 MiB를 초과했습니다.")
            model = str(body.get("model") or DEFAULT_MODEL)
            if model != DEFAULT_MODEL and model not in OPENAI_MODELS:
                raise ValueError(f"지원되지 않는 모델입니다: {model}")
            case = Case(str(body["description"]), files,
                        str(body.get("flag_regex") or DEFAULT_FLAG_REGEX),
                        bool(body.get("docker_python", False)),
                        tcp_endpoint=str(body.get("tcp_endpoint") or ""),
                        category=str(body.get("category") or "auto"),
                        allow_mismatch=bool(body.get("allow_mismatch", False)))
        except (ValueError, KeyError, TypeError, binascii.Error, json.JSONDecodeError) as exc:
            return self._reply(400, {"error": str(exc)})
        job = {"status": "queued", "events": [], "result": None, "error": None}
        with LOCK:
            JOBS[case.id] = job

        def update(message):
            with LOCK:
                job["events"].append(message)

        def work():
            with RUN_LOCK:
                with LOCK:
                    job["status"] = "running"
                case.event = update
                try:
                    result = case.solve(model=model)
                    with LOCK:
                        job["result"] = result
                        job["status"] = "done"
                except Exception as exc:
                    with LOCK:
                        job["error"] = str(exc)
                        job["status"] = "failed"
        threading.Thread(target=work, daemon=True).start()
        return self._reply(202, {"job_id": case.id})


def serve(open_browser=True):
    address = f"http://{HOST}:{PORT}"
    try:
        server = ThreadingHTTPServer((HOST, PORT), Handler)
    except OSError as exc:
        if getattr(exc, "winerror", None) == 10048 or "10048" in str(exc) or "Address already in use" in str(exc):
            print(f"이미 {address} 에서 CTF 도우미가 실행 중입니다. 브라우저에서 {address} 를 열거나 새로고침하세요.", flush=True)
            if open_browser:
                webbrowser.open(address)
            return
        raise
    print(f"CTF 도우미: {address} (종료: Ctrl+C)", flush=True)
    if open_browser:
        webbrowser.open(address)
    try:
        server.serve_forever(poll_interval=.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    serve()
