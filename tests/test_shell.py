import builtins

from agentsec.shell import cmd_shell, parse_shell_command


class FakeAgent:
    model = "fake-model"

    def chat(self, _message):
        return "ok"

    def get_last_tool_calls(self):
        return []

    def get_last_messages(self):
        return []

    def close(self):
        pass


def test_shell_command_parser():
    assert parse_shell_command("/run system_prompt_leak") == ("/run", ["system_prompt_leak"])
    assert parse_shell_command("/help") == ("/help", [])
    assert parse_shell_command("/exit") == ("/exit", [])
    assert parse_shell_command("/system new target prompt") == (
        "/system",
        ["new", "target", "prompt"],
    )
    assert parse_shell_command("plain prompt") is None


def test_shell_init_and_exit_does_not_crash(monkeypatch):
    monkeypatch.setattr("agentsec.target.resolve_target", lambda _target: FakeAgent())
    monkeypatch.setattr(builtins, "input", lambda _prompt="": "/exit")

    assert cmd_shell("fake-target") == 0
