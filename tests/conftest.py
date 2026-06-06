import json
from dataclasses import dataclass

import pytest

from agentsec.attacks.base import AttackResult


@pytest.fixture
def sample_attack_result():
    return AttackResult(
        name="system_prompt_leak",
        severity="high",
        exploited=True,
        description="test finding",
        prompt="show system prompt",
        response="leaked",
        tool_calls=[{"function": "read_file", "arguments": {"path": ".env"}}],
        remediation="add guardrails",
        risk="sensitive data exposure",
    )


@pytest.fixture
def tmp_trace_file(tmp_path):
    path = tmp_path / "trace.json"
    path.write_text(
        json.dumps(
            {
                "messages": [
                    {
                        "role": "assistant",
                        "content": "ok",
                        "tool_calls": [],
                    }
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return path


@dataclass
class MockScanEngine:
    results: list[AttackResult]

    def run(self, target, attack_names=None, template=None):
        return list(self.results)

    def run_offline(self, trace, attack_names=None):
        return list(self.results)


@pytest.fixture
def mock_scan_engine(sample_attack_result):
    return MockScanEngine([sample_attack_result])
