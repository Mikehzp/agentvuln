import json
import sys
import types

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


def test_progress_bar_wraps_attack_loop(monkeypatch, tmp_trace_file):
    calls = []

    def fake_tqdm(items, desc):
        calls.append({"items": list(items), "desc": desc})
        return calls[0]["items"]

    monkeypatch.setitem(sys.modules, "tqdm", types.SimpleNamespace(tqdm=fake_tqdm))

    results = ScanEngine().run(str(tmp_trace_file), ["system_prompt_leak"], show_progress=True)

    assert len(results) == 1
    assert calls
    assert calls[0]["desc"] == "Scanning"
    assert calls[0]["items"][0][0] == "system_prompt_leak"


def test_exploited_offline_result_gets_recommendation():
    trace = [
        {
            "role": "assistant",
            "content": "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----",
        }
    ]

    results = ScanEngine().run_offline(trace, ["data_leak"], show_progress=False)

    assert len(results) == 1
    assert results[0].exploited is True
    assert "output filter" in results[0].recommendation
