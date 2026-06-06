import json

from agentsec.engine import ScanEngine


def test_offline_trace_reads_utf8_json(tmp_path):
    trace_path = tmp_path / "trace.json"
    trace_path.write_text(
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

    results = ScanEngine().run(str(trace_path), ["system_prompt_leak"])

    assert len(results) == 1
    assert results[0].name == "system_prompt_leak"


def test_offline_trace_gbk_file_does_not_crash(tmp_path):
    trace_path = tmp_path / "trace.json"
    trace_path.write_bytes('{"messages": [{"role": "assistant", "content": "中文"}]}'.encode("gbk"))

    results = ScanEngine().run(str(trace_path), ["system_prompt_leak"])

    assert results == []
