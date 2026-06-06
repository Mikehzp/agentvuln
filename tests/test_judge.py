from agentsec.judge import LLMJudge, ToolCallAnalyzer


class FakeMessage:
    def __init__(self, content):
        self.content = content


class FakeChoice:
    def __init__(self, content):
        self.message = FakeMessage(content)


class FakeResponse:
    def __init__(self, content):
        self.choices = [FakeChoice(content)]


class FakeCompletions:
    def __init__(self, content=None, error=None):
        self.content = content
        self.error = error

    def create(self, **_kwargs):
        if self.error:
            raise self.error
        return FakeResponse(self.content)


class FakeChat:
    def __init__(self, content=None, error=None):
        self.completions = FakeCompletions(content, error)


class FakeClient:
    def __init__(self, content=None, error=None):
        self.chat = FakeChat(content, error)


def judge_with(content=None, error=None):
    judge = LLMJudge.__new__(LLMJudge)
    judge._client = FakeClient(content, error)
    judge._model = "test-model"
    return judge


def test_llm_judge_parses_json_from_regex_fallback():
    judge = judge_with('prefix {"exploited": true, "confidence": "high", "reason": "tool used", "evidence": ["x"]} suffix')

    verdict = judge.judge("data_leak", "prompt", "response", [], "high")

    assert verdict.exploited is True
    assert verdict.confidence == "high"
    assert verdict.reason == "tool used"
    assert verdict.evidence == ["x"]


def test_tool_call_analyzer_classifies_severity():
    assert ToolCallAnalyzer.classify_tool_risk("execute_command") == "critical"
    assert ToolCallAnalyzer.classify_tool_risk("write_file") == "high"
    assert ToolCallAnalyzer.classify_tool_risk("read_file") == "medium"
    assert ToolCallAnalyzer.classify_tool_risk("unknown") == "low"


def test_llm_judge_invalid_json_does_not_crash():
    verdict = judge_with("not json").judge("data_leak", "prompt", "", [], "high")

    assert verdict.exploited is False
    assert verdict.confidence == "low"
    assert verdict.layer == "llm_judge"


def test_llm_judge_empty_response_does_not_crash():
    verdict = judge_with("").judge("data_leak", "prompt", "", [], "high")

    assert verdict.exploited is False
    assert verdict.confidence == "low"
    assert verdict.layer == "llm_judge"
