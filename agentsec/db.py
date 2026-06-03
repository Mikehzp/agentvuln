"""
Database layer for agentsec — stores scan results, attack templates, compatibility data.

All security scan data goes here instead of memory.
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from agentsec.attacks.base import AttackResult

DB_PATH = Path(__file__).parent.parent / "data" / "agentsec.db"


# ─── Schema ─────────────────────────────────────────────────────

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scan_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    target          TEXT NOT NULL,
    provider        TEXT DEFAULT '',
    model           TEXT DEFAULT '',
    template        TEXT DEFAULT '',
    total_tests     INTEGER DEFAULT 0,
    passed          INTEGER DEFAULT 0,
    failed          INTEGER DEFAULT 0,
    duration_seconds REAL DEFAULT 0,
    status          TEXT DEFAULT 'completed',
    error_message   TEXT DEFAULT '',
    created_at      TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS attack_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id     INTEGER NOT NULL,
    name            TEXT NOT NULL,
    severity        TEXT NOT NULL,
    exploited       INTEGER NOT NULL DEFAULT 0,
    description     TEXT DEFAULT '',
    prompt          TEXT DEFAULT '',
    response        TEXT DEFAULT '',
    tool_calls_json TEXT DEFAULT '[]',
    trace_json      TEXT DEFAULT '[]',
    remediation     TEXT DEFAULT '',
    risk            TEXT DEFAULT '',
    created_at      TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS attack_templates (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT UNIQUE NOT NULL,
    severity        TEXT NOT NULL,
    description     TEXT DEFAULT '',
    risk            TEXT DEFAULT '',
    remediation     TEXT DEFAULT '',
    yaml_content    TEXT DEFAULT '',
    created_at      TEXT DEFAULT (datetime('now')),
    updated_at      TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS compatibility (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    target          TEXT NOT NULL,
    provider        TEXT DEFAULT '',
    model           TEXT DEFAULT '',
    total           INTEGER DEFAULT 0,
    passed          INTEGER DEFAULT 0,
    vulnerable      INTEGER DEFAULT 0,
    results_json    TEXT DEFAULT '[]',
    created_at      TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_scan_runs_target ON scan_runs(target);
CREATE INDEX IF NOT EXISTS idx_scan_runs_timestamp ON scan_runs(timestamp);
CREATE INDEX IF NOT EXISTS idx_attack_results_scan ON attack_results(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_attack_results_name ON attack_results(name);
CREATE INDEX IF NOT EXISTS idx_attack_results_exploited ON attack_results(exploited);
CREATE INDEX IF NOT EXISTS idx_compatibility_target ON compatibility(target);
"""


# ─── Connection helper ──────────────────────────────────────────

def get_conn(db_path: Optional[Path] = None) -> sqlite3.Connection:
    path = db_path or DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: Optional[Path] = None):
    """Create/upgrade schema."""
    conn = get_conn(db_path)
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    conn.close()


# ─── Scan Runs ──────────────────────────────────────────────────

def save_scan_run(
    target: str,
    results: list[AttackResult],
    provider: str = "",
    model: str = "",
    template: str = "",
    duration_seconds: float = 0,
    status: str = "completed",
    error_message: str = "",
) -> int:
    """Save a scan run and its attack results. Returns scan_run_id."""
    init_db()
    conn = get_conn()
    try:
        total = len(results)
        passed = sum(1 for r in results if not r.exploited)
        failed = sum(1 for r in results if r.exploited)

        cur = conn.execute("""
            INSERT INTO scan_runs
                (timestamp, target, provider, model, template,
                 total_tests, passed, failed, duration_seconds, status, error_message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().isoformat(),
            target, provider, model, template,
            total, passed, failed, duration_seconds, status, error_message,
        ))
        scan_run_id = cur.lastrowid

        for r in results:
            conn.execute("""
                INSERT INTO attack_results
                    (scan_run_id, name, severity, exploited, description,
                     prompt, response, tool_calls_json, trace_json, remediation, risk)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_run_id,
                r.name, r.severity, 1 if r.exploited else 0, r.description,
                r.prompt, r.response,
                json.dumps(r.tool_calls, ensure_ascii=False),
                json.dumps(r.trace, ensure_ascii=False),
                r.remediation, r.risk,
            ))

        conn.commit()
        return scan_run_id
    finally:
        conn.close()


def get_recent_scan_runs(limit: int = 10) -> list[dict]:
    """Get most recent scan runs."""
    conn = get_conn()
    try:
        rows = conn.execute("""
            SELECT id, timestamp, target, provider, model,
                   total_tests, passed, failed, duration_seconds, status
            FROM scan_runs
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_scan_run(scan_run_id: int) -> Optional[dict]:
    """Get a scan run with its attack results."""
    conn = get_conn()
    try:
        run = conn.execute("SELECT * FROM scan_runs WHERE id = ?", (scan_run_id,)).fetchone()
        if not run:
            return None
        results = conn.execute("""
            SELECT * FROM attack_results WHERE scan_run_id = ? ORDER BY id
        """, (scan_run_id,)).fetchall()
        return {**dict(run), "results": [dict(r) for r in results]}
    finally:
        conn.close()


def get_exploited_results(target: str = "", limit: int = 20) -> list[dict]:
    """Get most recent exploited (vulnerable) findings."""
    conn = get_conn()
    try:
        if target:
            rows = conn.execute("""
                SELECT ar.*, sr.target, sr.timestamp as scan_timestamp
                FROM attack_results ar
                JOIN scan_runs sr ON ar.scan_run_id = sr.id
                WHERE ar.exploited = 1 AND sr.target = ?
                ORDER BY ar.id DESC
                LIMIT ?
            """, (target, limit)).fetchall()
        else:
            rows = conn.execute("""
                SELECT ar.*, sr.target, sr.timestamp as scan_timestamp
                FROM attack_results ar
                JOIN scan_runs sr ON ar.scan_run_id = sr.id
                WHERE ar.exploited = 1
                ORDER BY ar.id DESC
                LIMIT ?
            """, (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ─── Templates ──────────────────────────────────────────────────

def save_template(
    name: str, severity: str,
    description: str = "", risk: str = "", remediation: str = "",
    yaml_content: str = "",
) -> int:
    """Insert or update an attack template."""
    init_db()
    conn = get_conn()
    try:
        existing = conn.execute(
            "SELECT id FROM attack_templates WHERE name = ?", (name,)
        ).fetchone()
        if existing:
            conn.execute("""
                UPDATE attack_templates
                SET severity=?, description=?, risk=?, remediation=?,
                    yaml_content=?, updated_at=datetime('now')
                WHERE name=?
            """, (severity, description, risk, remediation, yaml_content, name))
            return existing["id"]
        else:
            cur = conn.execute("""
                INSERT INTO attack_templates
                    (name, severity, description, risk, remediation, yaml_content)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (name, severity, description, risk, remediation, yaml_content))
            conn.commit()
            return cur.lastrowid
    finally:
        conn.close()


def list_templates() -> list[dict]:
    """List all stored attack templates."""
    conn = get_conn()
    try:
        rows = conn.execute("""
            SELECT id, name, severity, description, risk, created_at, updated_at
            FROM attack_templates
            ORDER BY name
        """).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ─── Compatibility ──────────────────────────────────────────────

def save_compatibility(entry: dict):
    """Save a compatibility matrix entry."""
    init_db()
    conn = get_conn()
    try:
        conn.execute("""
            INSERT INTO compatibility
                (timestamp, target, provider, model,
                 total, passed, vulnerable, results_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            entry.get("timestamp", datetime.now().isoformat()),
            entry.get("target", ""),
            entry.get("provider", ""),
            entry.get("model", ""),
            entry.get("total", 0),
            entry.get("passed", 0),
            entry.get("vulnerable", 0),
            json.dumps(entry.get("results", []), ensure_ascii=False),
        ))
        conn.commit()
    finally:
        conn.close()


def get_compatibility(target: str = "") -> list[dict]:
    """Get compatibility matrix entries."""
    conn = get_conn()
    try:
        if target:
            rows = conn.execute("""
                SELECT * FROM compatibility WHERE target = ? ORDER BY id DESC
            """, (target,)).fetchall()
        else:
            rows = conn.execute("""
                SELECT * FROM compatibility ORDER BY id DESC LIMIT 20
            """).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ─── Stats / Summary ────────────────────────────────────────────

def get_summary(target: str = "") -> dict:
    """Get aggregated stats across all scan runs."""
    conn = get_conn()
    try:
        if target:
            run = conn.execute("""
                SELECT COUNT(*) as scan_count,
                       SUM(total_tests) as total_tests,
                       SUM(failed) as total_vulnerable
                FROM scan_runs WHERE target = ?
            """, (target,)).fetchone()
        else:
            run = conn.execute("""
                SELECT COUNT(*) as scan_count,
                       SUM(total_tests) as total_tests,
                       SUM(failed) as total_vulnerable
                FROM scan_runs
            """).fetchone()

        # Top vulnerabilities
        vuln_query = """
            SELECT ar.name, ar.severity, COUNT(*) as count
            FROM attack_results ar
            JOIN scan_runs sr ON ar.scan_run_id = sr.id
            WHERE ar.exploited = 1
        """
        params = []
        if target:
            vuln_query += " AND sr.target = ?"
            params.append(target)
        vuln_query += " GROUP BY ar.name ORDER BY count DESC LIMIT 10"

        top_vulns = conn.execute(vuln_query, params).fetchall()

        # Severity breakdown
        sev_query = """
            SELECT ar.severity, COUNT(*) as count
            FROM attack_results ar
            JOIN scan_runs sr ON ar.scan_run_id = sr.id
            WHERE ar.exploited = 1
        """
        if target:
            sev_query += " AND sr.target = ?"
            params_sev = [target]
        else:
            params_sev = []
        sev_query += " GROUP BY ar.severity ORDER BY count DESC"
        by_severity = conn.execute(sev_query, params_sev).fetchall()

        return {
            "scan_count": run["scan_count"],
            "total_tests": run["total_tests"] or 0,
            "total_vulnerable": run["total_vulnerable"] or 0,
            "top_vulnerabilities": [dict(v) for v in top_vulns],
            "by_severity": {r["severity"]: r["count"] for r in by_severity},
        }
    finally:
        conn.close()


# ─── Init on import ─────────────────────────────────────────────

init_db()
