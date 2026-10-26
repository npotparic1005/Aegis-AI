"""SQLite-backed memory.

Persists sessions, the actions taken in each, and the findings
produced. This is what lets the agent hold state across a long
test and what the report is built from.

It also doubles as a structured audit trail: every action, with
its policy decision, is recorded here.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    engagement   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS actions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   INTEGER NOT NULL,
    tool         TEXT NOT NULL,
    target       TEXT NOT NULL,
    command      TEXT NOT NULL,
    policy_ok    INTEGER NOT NULL,
    policy_reason TEXT NOT NULL,
    executed     INTEGER NOT NULL DEFAULT 0,
    success        INTEGER,
    result_summary TEXT,
    error          TEXT,
    created_at   TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   INTEGER NOT NULL,
    action_id    INTEGER,
    host         TEXT,
    summary      TEXT,
    data         TEXT,
    created_at   TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Session:
    id: int
    name: str
    engagement: str


class Database:
    def __init__(self, path: str) -> None:
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        # Migrate DBs created before result columns existed.
        for col, decl in (("success", "INTEGER"), ("result_summary", "TEXT"), ("error", "TEXT")):
            try:
                self.conn.execute(f"ALTER TABLE actions ADD COLUMN {col} {decl}")
            except sqlite3.OperationalError:
                pass
        for table, col, decl in (("actions", "params", "TEXT"),
                                 ("sessions", "run_context", "TEXT"),
                                 ("sessions", "conclusion", "TEXT")):
            columns = {r["name"] for r in self.conn.execute(f"PRAGMA table_info({table})")}
            if col not in columns:
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
        self.conn.commit()

    # ---- sessions -----------------------------------------------------

    def create_session(self, name: str, engagement: str) -> Session:
        cur = self.conn.execute(
            "INSERT INTO sessions (name, engagement, created_at) VALUES (?, ?, ?)",
            (name, engagement, _now()),
        )
        self.conn.commit()
        return Session(id=cur.lastrowid, name=name, engagement=engagement)

    def close_session(self, session_id: int) -> None:
        self.conn.execute(
            "UPDATE sessions SET status = 'closed' WHERE id = ?", (session_id,)
        )
        self.conn.commit()

    def set_run_context(self, session_id: int, objective: str, targets: list[str],
                        intent: dict | None = None) -> None:
        context = {"objective": objective, "targets": targets}
        if intent is not None:
            context["intent"] = intent
        self.conn.execute("UPDATE sessions SET run_context = ? WHERE id = ?",
                          (json.dumps(context), session_id))
        self.conn.commit()

    def record_conclusion(self, session_id: int, conclusion: dict) -> None:
        self.conn.execute("UPDATE sessions SET conclusion = ? WHERE id = ?",
                          (json.dumps(conclusion), session_id))
        self.conn.commit()

    def get_run_context(self, session_id: int) -> dict:
        row = self.conn.execute("SELECT run_context FROM sessions WHERE id = ?", (session_id,)).fetchone()
        return json.loads(row[0]) if row and row[0] else {}

    def get_conclusion(self, session_id: int) -> dict:
        row = self.conn.execute("SELECT conclusion FROM sessions WHERE id = ?", (session_id,)).fetchone()
        return json.loads(row[0]) if row and row[0] else {}

    # ---- actions ------------------------------------------------------

    def record_action(
        self,
        session_id: int,
        tool: str,
        target: str,
        command: str,
        policy_ok: bool,
        policy_reason: str,
        executed: bool,
        params: dict[str, Any] | None = None,
    ) -> int:
        cur = self.conn.execute(
            """INSERT INTO actions
               (session_id, tool, target, command, policy_ok, policy_reason, executed, created_at, params)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (session_id, tool, target, command, int(policy_ok), policy_reason,
             int(executed), _now(), json.dumps(params) if params is not None else None),
        )
        self.conn.commit()
        return cur.lastrowid

    def record_result(self, action_id: int, success: bool, summary: str, error: str) -> None:
        """Persist the outcome of a run -- including failures -- so the
        planner's history reflects *why* something didn't work, not just
        whether it ran."""
        self.conn.execute(
            "UPDATE actions SET success = ?, result_summary = ?, error = ? WHERE id = ?",
            (int(success), summary, error, action_id),
        )
        self.conn.commit()

    # ---- findings -----------------------------------------------------

    def add_finding(
        self,
        session_id: int,
        action_id: int | None,
        host: str,
        summary: str,
        data: dict[str, Any],
    ) -> None:
        self.conn.execute(
            """INSERT INTO findings (session_id, action_id, host, summary, data, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (session_id, action_id, host, summary, json.dumps(data), _now()),
        )
        self.conn.commit()

    def get_findings(self, session_id: int) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT host, summary, data, created_at FROM findings WHERE session_id = ? ORDER BY id",
            (session_id,),
        ).fetchall()
        out = []
        for r in rows:
            out.append(
                {
                    "host": r["host"],
                    "summary": r["summary"],
                    "data": json.loads(r["data"]) if r["data"] else {},
                    "created_at": r["created_at"],
                }
            )
        return out

    def get_actions(self, session_id: int) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT id, tool, target, command, policy_ok, policy_reason, executed, created_at, "
            "success, result_summary, error, params "
            "FROM actions WHERE session_id = ? ORDER BY id",
            (session_id,),
        ).fetchall()
        return [{**dict(r), "params": json.loads(r["params"]) if r["params"] else None} for r in rows]

    def close(self) -> None:
        self.conn.close()
