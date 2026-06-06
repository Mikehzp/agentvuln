from agentsec.attacks.base import AttackResult
from agentsec import db


def test_get_conn_read_only_opens_existing_database(tmp_path):
    db_path = tmp_path / "agentsec.db"
    db.init_db(db_path)

    conn = db.get_conn(db_path, read_only=True)
    try:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    finally:
        conn.close()

    assert any(row["name"] == "scan_runs" for row in rows)


def test_save_scan_run_and_get_recent_runs_use_tmp_db(tmp_path, monkeypatch):
    db_path = tmp_path / "agentsec.db"
    monkeypatch.setattr(db, "DB_PATH", db_path)
    results = [
        AttackResult(name="system_prompt_leak", severity="high", exploited=True),
        AttackResult(name="dos_attack", severity="low", exploited=False),
    ]

    scan_id = db.save_scan_run("target", results, provider="openai", model="gpt-test")
    runs = db.get_recent_scan_runs(limit=1)

    assert scan_id > 0
    assert len(runs) == 1
    assert runs[0]["target"] == "target"
    assert runs[0]["provider"] == "openai"
    assert runs[0]["model"] == "gpt-test"
    assert runs[0]["total_tests"] == 2
    assert runs[0]["passed"] == 1
    assert runs[0]["failed"] == 1
