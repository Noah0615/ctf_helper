"""CTF Helper - Cross-Run Knowledge Sharing & History Transfer Engine."""
from __future__ import annotations

import json
from pathlib import Path
import re

def get_results_dir() -> Path:
    p1 = Path("results/ctf_helper")
    if p1.is_dir() and any((f / "result.json").is_file() for f in p1.iterdir() if f.is_dir()):
        return p1
    p2 = Path("../results/ctf_helper")
    if p2.is_dir() and any((f / "result.json").is_file() for f in p2.iterdir() if f.is_dir()):
        return p2
    return p1

RESULTS_DIR = get_results_dir()



def find_related_runs(description: str, file_names: list[str] = None, web_origin: str = "", current_run_id: str = "") -> list[dict]:
    """
    Finds past analysis runs in results/ctf_helper that match the current challenge
    by description, target endpoint, or file names.
    """
    if not RESULTS_DIR.is_dir():
        return []

    file_names_set = set(file_names or [])
    desc_clean = description.strip()
    related = []

    for folder in sorted(RESULTS_DIR.iterdir(), reverse=True):
        if not folder.is_dir() or folder.name == current_run_id:
            continue
        res_file = folder / "result.json"
        prob_file = folder / "problem.txt"
        case_file = folder / "case.json"

        if not res_file.is_file():
            continue

        try:
            is_match = False
            match_reasons = []

            # 1. Match by problem description
            if prob_file.is_file():
                prob_text = prob_file.read_text(encoding="utf-8").strip()
                if prob_text and desc_clean:
                    # Check substring or significant overlap
                    if prob_text in desc_clean or desc_clean in prob_text:
                        is_match = True
                        match_reasons.append("문제 설명 일치")
                    elif len(prob_text) > 30 and len(desc_clean) > 30:
                        # Check first 60 chars
                        if prob_text[:60] == desc_clean[:60]:
                            is_match = True
                            match_reasons.append("문제 서두 일치")

            # 2. Match by endpoint / URL
            if web_origin and case_file.is_file():
                case_meta = json.loads(case_file.read_text(encoding="utf-8"))
                past_endpoint = case_meta.get("tcp_endpoint", "")
                if past_endpoint:
                    # Clean host and port
                    origin_clean = web_origin.replace("http://", "").replace("https://", "").strip("/")
                    endpoint_clean = past_endpoint.replace("http://", "").replace("https://", "").strip("/")
                    if origin_clean and (origin_clean in endpoint_clean or endpoint_clean in origin_clean):
                        is_match = True
                        match_reasons.append("문제 서버 주소 일치")

            # 3. Match by file names overlap
            if not is_match and file_names_set and case_file.is_file():
                case_meta = json.loads(case_file.read_text(encoding="utf-8"))
                past_files = set(case_meta.get("uploaded_names", []))
                common_files = file_names_set.intersection(past_files)
                # Ignore trivial common files like flag.txt or dummy.txt
                meaningful_common = [f for f in common_files if Path(f).name.lower() not in {"flag.txt", "flag", "dummy.txt", ".gitignore"}]
                if len(meaningful_common) >= 1:
                    is_match = True
                    match_reasons.append(f"문제 파일 일치({len(meaningful_common)}개)")

            if is_match:
                data = json.loads(res_file.read_text(encoding="utf-8"))
                model = data.get("model", "unknown")
                flags = [item.get("flag") for item in data.get("flag_candidates", []) if isinstance(item, dict) and item.get("flag")]
                scripts = [s.get("name") for s in data.get("solution_scripts", []) if isinstance(s, dict) and s.get("name")]
                scripts_data = data.get("solution_scripts", [])
                answer_snippet = str(data.get("answer", ""))[:350].strip()

                reqs = []
                for r in data.get("requests", []):
                    if isinstance(r, dict) and r.get("path"):
                        reqs.append(f"{r.get('method', 'GET')} {r.get('path')}")

                related.append({
                    "run_id": folder.name,
                    "model": model,
                    "match_reasons": match_reasons,
                    "flags": list(dict.fromkeys(flags)),
                    "scripts": scripts,
                    "scripts_data": scripts_data,
                    "requests": list(dict.fromkeys(reqs))[:8],
                    "answer_summary": answer_snippet
                })
        except Exception:
            continue

    # Sort: runs with flags first, then newer runs
    related.sort(key=lambda r: (len(r["flags"]) > 0, len(r["scripts"]) > 0, r["run_id"]), reverse=True)
    return related


def format_past_runs_knowledge(related_runs: list[dict], max_runs: int = 3) -> str:
    """
    Formats related past runs into an informative context section for the agent.
    """
    if not related_runs:
        return ""

    lines = [
        "\n\n=======================================================",
        "[과거 분석 기록 참조 (Cross-Model Knowledge Sharing)]",
        "동일한 문제(또는 동일 서버)에 대해 이전에 수행된 다른 모델의 분석 기록이 감지되었습니다.",
        "이전 모델이 발견한 유효 경로, 플래그 후보, 스크립트를 참고하여 분석 시간을 단축하세요:",
    ]

    for idx, r in enumerate(related_runs[:max_runs], 1):
        lines.append(f"\n* [기록 {idx}] 모델: {r['model']} (실행 ID: {r['run_id']})")
        lines.append(f"  - 연계 사유: {', '.join(r['match_reasons'])}")
        if r["flags"]:
            lines.append(f"  - 발견된 플래그 후보: {', '.join(r['flags'])}")
        if r["requests"]:
            lines.append(f"  - 시도된 주요 요청: {', '.join(r['requests'][:5])}")
        if r["scripts"]:
            lines.append(f"  - 저장된 풀이 스크립트: {', '.join(r['scripts'])}")
        if r["answer_summary"]:
            lines.append(f"  - 이전 결론 요약:\n    {r['answer_summary'][:220]}...")

    lines.append("\n[주의사항]: 이전 모델의 주관적 결론(실패 사유 등)은 잘못된 입력이나 권한 착각일 수 있으므로 맹신하지 말고, 객관적 관찰값(플래그 형식, 유효 경로)을 토대로 직접 검증하세요.")
    lines.append("=======================================================")
    return "\n".join(lines)


def search_past_runs(query: str, max_results: int = 5) -> str:
    """
    Searches past analysis runs by keyword in problem text, answers, or solution scripts.
    """
    if not RESULTS_DIR.is_dir():
        return "과거 분석 기록 디렉터리를 찾을 수 없습니다."

    q_lower = query.lower().strip()
    if not q_lower:
        return "검색어를 입력하세요."

    matches = []
    for folder in sorted(RESULTS_DIR.iterdir(), reverse=True):
        if not folder.is_dir():
            continue
        res_file = folder / "result.json"
        prob_file = folder / "problem.txt"

        if not res_file.is_file():
            continue

        try:
            data = json.loads(res_file.read_text(encoding="utf-8"))
            prob_text = prob_file.read_text(encoding="utf-8") if prob_file.is_file() else ""
            answer = str(data.get("answer", ""))
            all_text = f"{prob_text}\n{answer}\n{folder.name}".lower()

            # Check if query matches
            if q_lower in all_text or any(q_lower in str(s.get("code", "")).lower() for s in data.get("solution_scripts", [])):
                flags = [item.get("flag") for item in data.get("flag_candidates", []) if isinstance(item, dict) and item.get("flag")]
                matches.append({
                    "run_id": folder.name,
                    "model": data.get("model", ""),
                    "flags": list(dict.fromkeys(flags)),
                    "preview": prob_text[:120].strip(),
                    "answer_preview": answer[:200].strip(),
                    "scripts": [s.get("name") for s in data.get("solution_scripts", []) if isinstance(s, dict)]
                })
        except Exception:
            continue

    if not matches:
        return f"'{query}'에 대한 과거 분석 기록을 찾을 수 없습니다."

    lines = [f"[과거 분석 기록 검색 결과: '{query}' (총 {len(matches)}건 발견)]"]
    for m in matches[:max_results]:
        lines.append(f"\n- 실행 ID: {m['run_id']} (모델: {m['model']})")
        lines.append(f"  * 문제 요약: {m['preview'][:80]}...")
        if m["flags"]:
            lines.append(f"  * 발견된 플래그: {', '.join(m['flags'])}")
        if m["scripts"]:
            lines.append(f"  * 풀이 스크립트: {', '.join(m['scripts'])}")
        lines.append(f"  * 결론 요약: {m['answer_preview'][:120]}...")

    return "\n".join(lines)
