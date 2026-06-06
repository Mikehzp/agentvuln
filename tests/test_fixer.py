from agentsec.attacks.base import AttackResult
from agentsec.fixer import apply_all_fixes, get_fixes_for_result
from agentsec.fixer import SystemPromptLeakFix


def exploited(name):
    return AttackResult(name=name, severity="high", exploited=True)


def test_known_fixers_are_registered():
    expected = {
        "system_prompt_leak": "system_prompt_leak",
        "data_leak": "data_leak",
        "privilege_escalation": "privilege_escalation",
        "dos_attack": "dos_attack",
    }

    for attack_name, fix_name in expected.items():
        fixes = get_fixes_for_result(exploited(attack_name))
        assert [fix.name for fix in fixes] == [fix_name]


def test_dry_run_does_not_apply_fix(monkeypatch):
    called = []
    result = exploited("system_prompt_leak")
    fix = get_fixes_for_result(result)[0]

    monkeypatch.setattr(fix, "apply", lambda _result: called.append(True))

    fix_results = apply_all_fixes([result], dry_run=True)

    assert called == []
    assert len(fix_results) == 1
    assert fix_results[0].success is True
    assert "DRY RUN" in fix_results[0].message


def test_fix_result_returns_recommendation_message():
    fix_results = apply_all_fixes([exploited("system_prompt_leak")], dry_run=True)

    assert fix_results[0].message
    assert fix_results[0].attack_name == "system_prompt_leak"


def test_fix_actually_fixes_system_prompt_leak(tmp_path, monkeypatch):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    hermes_dir = tmp_path / ".hermes"
    hermes_dir.mkdir()
    soul = hermes_dir / "SOUL.md"
    soul.write_text("base prompt", encoding="utf-8")

    fix_result = SystemPromptLeakFix().apply(exploited("system_prompt_leak"))

    assert fix_result.success is True
    assert "Security Guardrails" in soul.read_text(encoding="utf-8")


def test_fix_idempotent_system_prompt_leak(tmp_path, monkeypatch):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    hermes_dir = tmp_path / ".hermes"
    hermes_dir.mkdir()
    soul = hermes_dir / "SOUL.md"
    soul.write_text(SystemPromptLeakFix.GUARDRAIL.strip(), encoding="utf-8")

    first = SystemPromptLeakFix().apply(exploited("system_prompt_leak"))
    second = SystemPromptLeakFix().apply(exploited("system_prompt_leak"))

    content = soul.read_text(encoding="utf-8")
    assert first.success is True
    assert second.success is True
    assert content.count("Security Guardrails") == 1
