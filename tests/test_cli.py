from agentsec.attacks.base import AttackResult
from agentsec.cli import _should_fail


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
