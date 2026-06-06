import pytest

from agentsec import target
from agentsec import direct_target


class FakeDirectTarget:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.name = f"{kwargs.get('provider')}:{kwargs.get('model')}"


class FakeHermesTarget:
    name = "hermes"


class FakeOpenAI:
    def __init__(self, base_url=None, api_key=None):
        self.base_url = base_url
        self.api_key = api_key


def test_resolve_target_factory(monkeypatch):
    monkeypatch.setattr(target, "HermesAgentTarget", lambda: FakeHermesTarget())
    monkeypatch.setattr(target, "DirectAPITarget", lambda **kwargs: FakeDirectTarget(**kwargs))
    monkeypatch.setattr(
        target,
        "resolve_provider_config",
        lambda spec: {
            "provider": "deepseek" if spec in ("hermes", "hermes-fast") else spec.split(":", 1)[0],
            "base_url": "https://example.test/v1",
            "api_key": "test-key",
            "model": spec.split(":", 1)[1] if ":" in spec else "test-model",
        },
    )

    assert target.resolve_target("hermes").name == "hermes"
    hermes_fast = target.resolve_target("hermes-fast")
    openai_target = target.resolve_target("openai:gpt-4o")
    custom = target.resolve_target("api:https://example.test/v1:gpt-test")

    assert isinstance(hermes_fast, FakeDirectTarget)
    assert hermes_fast.kwargs["provider"] == "deepseek"
    assert openai_target.kwargs["provider"] == "openai"
    assert openai_target.kwargs["model"] == "gpt-4o"
    assert custom.kwargs["provider"] == "api"


def test_resolve_target_invalid_does_not_crash(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    cfg = target.resolve_provider_config("not-a-real-provider")

    assert cfg["provider"] == "openai"
    assert cfg["model"] == "not-a-real-provider"
    assert cfg["api_key"] == "test-key"


def test_resolve_provider_config_custom_api(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("openai_api_key", raising=False)
    monkeypatch.setenv("AGENTSEC_API_KEY", "test-key")

    cfg = target.resolve_provider_config("api:https://llm.example/v1:custom-model")

    assert cfg["provider"] == "custom"
    assert cfg["base_url"] == "https://llm.example/v1"
    assert cfg["model"] == "custom-model"
    assert cfg["api_key"] == "test-key"


def test_target_direct_api_target_init(monkeypatch):
    monkeypatch.setattr("openai.OpenAI", FakeOpenAI)

    instance = target.DirectAPITarget(
        provider="openai",
        base_url="https://example.test/v1",
        api_key="test-key",
        model="gpt-test",
    )

    assert instance.provider == "openai"
    assert instance.model == "gpt-test"
    assert instance._client.base_url == "https://example.test/v1"


def test_legacy_direct_api_target_init(monkeypatch):
    monkeypatch.setattr(direct_target, "OpenAI", FakeOpenAI)
    monkeypatch.setattr(
        direct_target,
        "load_credentials",
        lambda: {
            "provider": "openai",
            "base_url": "https://example.test/v1",
            "api_key": "test-key",
            "model": "gpt-test",
        },
    )

    instance = direct_target.DirectAPITarget()

    assert instance._model == "gpt-test"
    assert instance._client.api_key == "test-key"
