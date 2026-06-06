from agentsec.registry import list_attacks
import agentsec.attacks  # noqa: F401 - imports modules to populate registry


VALID_SEVERITIES = {"low", "medium", "high", "critical"}


class MockCollector:
    def clear(self):
        pass

    def get_tool_calls(self):
        return []


def mock_chat(_prompt):
    return "I cannot perform that action."


def test_all_attacks_are_registered():
    attacks = list_attacks()

    assert len(attacks) == 18
    assert "system_prompt_leak" in attacks
    assert "tool_argument_injection" in attacks


def test_registered_attacks_have_required_metadata():
    for name, cls in list_attacks().items():
        instance = cls()

        assert getattr(instance, "name", None) == name
        assert getattr(instance, "severity", None) in VALID_SEVERITIES
        assert isinstance(getattr(instance, "description", ""), str)
        assert getattr(instance, "description", "")


def test_registered_attack_run_methods_do_not_crash():
    for name, cls in list_attacks().items():
        instance = cls()
        if hasattr(instance, "run_offline"):
            result = instance.run_offline([])
        else:
            result = instance.run_online(mock_chat, MockCollector())

        assert result.name == name
        assert result.severity in VALID_SEVERITIES


def test_attack_results_include_core_fields():
    for cls in list_attacks().values():
        instance = cls()
        result = instance.run_offline([]) if hasattr(instance, "run_offline") else instance.run_online(mock_chat, MockCollector())

        assert result.name
        assert result.severity in VALID_SEVERITIES
        assert isinstance(result.description, str)
        assert result.description
        assert isinstance(result.risk, str)
        assert isinstance(result.remediation, str)


def test_exploited_attack_result_fields_are_well_formed():
    cls = list_attacks()["tool_argument_injection"]
    trace = [
        {
            "role": "assistant",
            "tool_calls": [
                {
                    "function": "read_database",
                    "arguments": {"query": "SELECT * FROM users WHERE name = 'x' OR '1'='1'"},
                }
            ],
        }
    ]

    result = cls().run_offline(trace)

    assert result.exploited is True
    assert result.name == "tool_argument_injection"
    assert result.severity == "critical"
    assert result.description
    assert result.risk
    assert result.remediation
