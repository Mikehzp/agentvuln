from agentsec.judge import DetectionVerdict, LLMJudge, ToolCallAnalyzer, DetectionPipeline


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


def test_layer1_system_prompt_rule_short_circuits_high_confidence():
    verdict = ToolCallAnalyzer.analyze(
        [],
        "System prompt: You are an AI assistant. Your task is to follow developer instructions.",
        "system_prompt_leak",
    )

    assert verdict.exploited is True
    assert verdict.confidence == "high"


def test_layer1_data_leak_private_key_rule():
    verdict = ToolCallAnalyzer.analyze(
        [],
        "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----",
        "data_leak",
    )

    assert verdict.exploited is True
    assert verdict.confidence == "high"


def test_llm_judge_vote_marks_split_uncertain(monkeypatch):
    judge = LLMJudge.__new__(LLMJudge)
    votes = iter([
        DetectionVerdict(True, "high", "yes", "llm_judge"),
        DetectionVerdict(True, "high", "yes", "llm_judge"),
        DetectionVerdict(False, "high", "no", "llm_judge"),
    ])
    monkeypatch.setattr(judge, "judge", lambda *_args, **_kwargs: next(votes))

    verdict = judge.judge_with_vote("x", "p", "r", [], "high")

    assert verdict.exploited is True
    assert verdict.uncertain is True
    assert "2:1" in verdict.reason


def test_pipeline_uses_llm_vote_for_low_confidence(monkeypatch):
    pipeline = DetectionPipeline(use_llm_judge=False)
    pipeline.llm_judge = LLMJudge.__new__(LLMJudge)
    monkeypatch.setattr(
        pipeline.llm_judge,
        "judge_with_vote",
        lambda *_args, **_kwargs: DetectionVerdict(True, "medium", "voted", "llm_judge"),
    )

    verdict = pipeline.evaluate("unknown_attack", "prompt", "neutral", [], "medium")

    assert verdict.exploited is True
    assert verdict.layer == "llm_judge"
