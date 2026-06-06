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
