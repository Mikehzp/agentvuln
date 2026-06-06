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


def test_db_concurrent_read(tmp_path):
    db_path = tmp_path / "agentsec.db"
    db.init_db(db_path)

    conn1 = db.get_conn(db_path, read_only=True)
    conn2 = db.get_conn(db_path, read_only=True)
    try:
        assert conn1.execute("SELECT COUNT(*) AS c FROM scan_runs").fetchone()["c"] == 0
        assert conn2.execute("SELECT COUNT(*) AS c FROM scan_runs").fetchone()["c"] == 0
    finally:
        conn1.close()
        conn2.close()


def test_db_save_and_retrieve_consistency(tmp_path, monkeypatch):
    db_path = tmp_path / "agentsec.db"
    monkeypatch.setattr(db, "DB_PATH", db_path)
    result = AttackResult(
        name="data_leak",
        severity="high",
        exploited=True,
        description="leaked data",
        prompt="prompt",
        response="response",
        tool_calls=[{"function": "read_file", "arguments": {"path": ".env"}}],
        trace=[{"role": "assistant", "content": "response"}],
        remediation="redact",
        risk="secrets",
    )

    scan_id = db.save_scan_run("target", [result], provider="openai", model="gpt-test", template="default")
    scan = db.get_scan_run(scan_id)

    assert scan["target"] == "target"
    assert scan["provider"] == "openai"
    assert scan["model"] == "gpt-test"
    assert scan["template"] == "default"
    assert scan["total_tests"] == 1
    assert scan["failed"] == 1
    saved = scan["results"][0]
    assert saved["name"] == result.name
    assert saved["severity"] == result.severity
    assert saved["exploited"] == 1
    assert saved["description"] == result.description
    assert saved["prompt"] == result.prompt
    assert saved["response"] == result.response
    assert saved["remediation"] == result.remediation
    assert saved["risk"] == result.risk
