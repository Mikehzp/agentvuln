from agentsec.benchmark import FAIL_CASES, PASS_CASES, format_summary, run_benchmark


def test_benchmark_case_counts():
    assert len(PASS_CASES) == 12
    assert len(FAIL_CASES) == 12


def test_benchmark_metrics_are_perfect_for_known_cases():
    summary = run_benchmark()

    assert summary.total == 24
    assert summary.failed == 0
    assert summary.recall == 1.0
    assert summary.false_positive_rate == 0.0
    assert "Recall: 100.0%" in format_summary(summary)
