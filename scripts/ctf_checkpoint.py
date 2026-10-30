"""CTF Helper v2.0 - SQLite Checkpoints & Durable Event Logger."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
import json
from pathlib import Path
import sqlite3
from typing import Any, Generator

from ctf_agent_state import SessionState

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_DIR = PROJECT_ROOT / ".runtime" / "ctf-helper"
RESULTS_DIR = PROJECT_ROOT / "results" / "ctf_helper"
DB_PATH = RUNTIME_DIR / "sessions.sqlite3"


@contextmanager
def get_connection(db_path: Path = DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        yield conn
    finally:
        conn.close()


def init_db(db_path: Path = DB_PATH) -> None:
    with get_connection(db_path) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                run_id TEXT PRIMARY KEY,
                root_id TEXT NOT NULL,
                parent_id TEXT,
                category TEXT,
                status TEXT,
                state_json TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                root_id TEXT NOT NULL,
                source_type TEXT,
                path_or_tool TEXT,
                sha256 TEXT,
                flag TEXT,
                role TEXT,
                status TEXT,
                content TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS lineage_budgets (
                root_id TEXT PRIMARY KEY,
                http_direct_used INTEGER DEFAULT 0,
                http_batch_used INTEGER DEFAULT 0,
                tcp_used INTEGER DEFAULT 0,
                total_steps INTEGER DEFAULT 0,
                updated_at TEXT
            )
        """)
        conn.commit()


class CheckpointStore:
    """Provides lossless state persistence and lineage budget tracking."""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        init_db(self.db_path)

    def save_session(self, state: SessionState, evidence_list: list[dict]) -> None:
        state_dict = state.to_dict()
        with get_connection(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO sessions (run_id, root_id, parent_id, category, status, state_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                state.run_id,
                state.root_id,
                state_dict.get("parent_id"),
                state.category,
                state.status,
                json.dumps(state_dict, ensure_ascii=False),
                state.created_at,
                datetime.now().isoformat()
            ))

            for item in evidence_list:
                ev_id = item.get("evidence_id") or f"ev_{item.get('flag', '')}_{item.get('source', '')[:20]}"
                conn.execute("""
                    INSERT OR REPLACE INTO evidence (evidence_id, run_id, root_id, source_type, path_or_tool, sha256, flag, role, status, content)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ev_id,
                    state.run_id,
                    state.root_id,
                    item.get("source_type", item.get("source", "")),
                    item.get("path_or_tool", ""),
                    item.get("sha256", ""),
                    item.get("flag", ""),
                    item.get("role", "candidate"),
                    item.get("status", ""),
                    item.get("content", "")[:3000]
                ))
            conn.commit()

    def load_session(self, run_id: str) -> tuple[SessionState | None, list[dict]]:
        with get_connection(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT state_json FROM sessions WHERE run_id = ?", (run_id,))
            row = cur.fetchone()
            if not row:
                return None, []
            state_data = json.loads(row[0])
            state = SessionState.from_dict(state_data)

            cur.execute("SELECT flag, source_type, role, status, content, sha256 FROM evidence WHERE run_id = ?", (run_id,))
            evidence = []
            for ev_row in cur.fetchall():
                evidence.append({
                    "flag": ev_row[0],
                    "source": ev_row[1],
                    "role": ev_row[2],
                    "status": ev_row[3],
                    "content": ev_row[4],
                    "sha256": ev_row[5],
                })
            return state, evidence

    def get_lineage_budget(self, root_id: str) -> dict:
        with get_connection(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT http_direct_used, http_batch_used, tcp_used, total_steps
                FROM lineage_budgets WHERE root_id = ?
            """, (root_id,))
            row = cur.fetchone()
            if not row:
                return {
                    "http_direct_used": 0,
                    "http_batch_used": 0,
                    "tcp_used": 0,
                    "total_steps": 0
                }
            return {
                "http_direct_used": row[0],
                "http_batch_used": row[1],
                "tcp_used": row[2],
                "total_steps": row[3],
            }

    def update_lineage_budget(self, root_id: str, http_direct_delta: int = 0,
                              http_batch_delta: int = 0, tcp_delta: int = 0,
                              steps_delta: int = 0) -> dict:
        with get_connection(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO lineage_budgets (root_id, http_direct_used, http_batch_used, tcp_used, total_steps, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(root_id) DO UPDATE SET
                    http_direct_used = http_direct_used + excluded.http_direct_used,
                    http_batch_used = http_batch_used + excluded.http_batch_used,
                    tcp_used = tcp_used + excluded.tcp_used,
                    total_steps = total_steps + excluded.total_steps,
                    updated_at = excluded.updated_at
            """, (
                root_id,
                http_direct_delta,
                http_batch_delta,
                tcp_delta,
                steps_delta,
                datetime.now().isoformat()
            ))
            conn.commit()
        return self.get_lineage_budget(root_id)


def append_event_log(run_id: str, event_type: str, payload: dict[str, Any]) -> None:
    """Append-only structured event logger to results/ctf_helper/<run_id>/events.jsonl."""
    log_dir = RESULTS_DIR / run_id
    log_dir.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now().isoformat(),
        "event_type": event_type,
        "payload": payload,
    }
    with (log_dir / "events.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
