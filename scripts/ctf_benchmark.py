"""CTF Helper v2.0 - Reproducible Benchmark Runner & Evaluator."""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import sys
import time

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from ctf_helper import Case, DEFAULT_MODEL
from ctf_verifier import ObjectiveVerifier


def run_benchmark(manifest_path: Path, output_dir: Path, model: str = DEFAULT_MODEL,
                  think_mode: str = "quick", repetitions: int = 1) -> dict:
    if not manifest_path.is_file():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    suites = manifest.get("suites", [])
    output_dir.mkdir(parents=True, exist_ok=True)

    results = []
    print(f"=== CTF Helper v2.0 Benchmark (Model: {model}, Mode: {think_mode}, Cases: {len(suites)}) ===")

    for suite in suites:
        case_id = suite["id"]
        print(f"\n[Running {case_id}] {suite.get('name')}")
        files = []
        for f in suite.get("files", []):
            raw = base64.b64decode(f["content_b64"])
            files.append((f["name"], raw))

        expected = suite.get("expected_flags", [])

        for rep in range(repetitions):
            start = time.monotonic()
            case = Case(
                description=suite["description"],
                files=files,
                flag_regex=suite.get("flag_regex", r"DH\{[^}\r\n]+\}"),
                category=suite.get("category", "auto")
            )
            try:
                res = case.solve(model=model, max_steps=10, think_mode=think_mode)
                elapsed = time.monotonic() - start

                # Evaluation
                eval_out = ObjectiveVerifier.evaluate_candidates(res.get("flag_observations", []))
                found_flags = eval_out["remote_flags"] + eval_out["tool_derived_flags"]
                solved = any(flag in expected for flag in found_flags) if expected else (len(found_flags) == 0 and len(eval_out["decoy_flags"]) > 0)
                fp = any(flag not in expected for flag in found_flags) if expected else False

                entry = {
                    "case_id": case_id,
                    "repetition": rep + 1,
                    "elapsed_seconds": round(elapsed, 2),
                    "solved": solved,
                    "false_positive": fp,
                    "decoy_isolated": len(eval_out["decoy_flags"]) > 0,
                    "metrics": res.get("metrics", {}),
                    "hypotheses_count": len(res.get("hypotheses", [])),
                    "result_status": res.get("result_status")
                }
                results.append(entry)
                print(f"  Rep {rep+1}: solved={solved}, fp={fp}, time={round(elapsed, 2)}s, status={res.get('result_status')}")
            except Exception as exc:
                print(f"  Rep {rep+1} failed with error: {exc}")
                results.append({
                    "case_id": case_id,
                    "repetition": rep + 1,
                    "error": str(exc),
                    "solved": False,
                })

    report_path = output_dir / f"benchmark_report_{think_mode}_{int(time.time())}.json"
    report_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nBenchmark completed. Report written to {report_path}")
    return {"results": results, "report_path": str(report_path)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CTF Helper v2.0 Benchmark Runner")
    parser.add_argument("--manifest", default=str(PROJECT_ROOT / "benchmarks" / "manifest.json"))
    parser.add_argument("--output", default=str(PROJECT_ROOT / "results" / "benchmarks"))
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--mode", default="quick", choices=["quick", "deep"])
    parser.add_argument("--reps", type=int, default=1)
    args = parser.parse_args()

    run_benchmark(Path(args.manifest), Path(args.output), model=args.model,
                  think_mode=args.mode, repetitions=args.reps)
