from agentsec.attacks.base import AttackResult
from agentsec.cli import _should_fail
from agentsec import cli


def test_fail_on_none_never_fails():
    results = [AttackResult(name="x", severity="critical", exploited=True)]

    assert _should_fail(results, "none") is False


def test_fail_on_thresholds():
    results = [
        AttackResult(name="low", severity="low", exploited=True),
        AttackResult(name="medium", severity="medium", exploited=True),
    ]

    assert _should_fail(results, "low") is True
    assert _should_fail(results, "medium") is True
    assert _should_fail(results, "high") is False
    assert _should_fail(results, "critical") is False


def test_fail_on_ignores_passed_findings():
    results = [AttackResult(name="critical", severity="critical", exploited=False)]

    assert _should_fail(results, "low") is False


def test_main_version(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["agentsec", "--version"])

    try:
        cli.main()
    except SystemExit as exc:
        assert exc.code == 0

    assert "agentsec v" in capsys.readouterr().out


def test_main_no_command(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["agentsec"])

    cli.main()

    assert "usage:" in capsys.readouterr().out


def test_main_invalid_command(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["agentsec", "not-a-command"])

    try:
        cli.main()
    except SystemExit as exc:
        assert exc.code == 2

    captured = capsys.readouterr()
    assert "invalid choice" in captured.err
