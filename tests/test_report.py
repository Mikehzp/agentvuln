from agentsec.attacks.base import AttackResult
from agentsec.report import ReportGenerator


def test_html_report_escapes_untrusted_fields():
    html = ReportGenerator().to_html(
        [
            AttackResult(
                name="x<script>",
                severity="high",
                exploited=True,
                description="<script>alert(1)</script>",
                prompt="<img src=x onerror=alert(1)>",
                risk="<b>risk</b>",
                remediation="<i>fix</i>",
            )
        ],
        "<b>target</b>",
    )

    assert "<script>alert(1)</script>" not in html
    assert "<img src=x onerror=alert(1)>" not in html
    assert "<b>target</b>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;b&gt;target&lt;/b&gt;" in html
