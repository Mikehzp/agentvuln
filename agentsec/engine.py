"""Scan Engine — orchestrates attack loading and execution (online and offline)."""

import sys
import json
import time
from pathlib import Path
from typing import Optional, Callable

from agentsec.registry import list_attacks
from agentsec.attacks.base import AttackResult


class ScanResults(list):
    """List-compatible scan results with metadata."""

    def __init__(self, results=None, duration_seconds: float = 0.0):
        super().__init__(results or [])
        self.duration_seconds = duration_seconds


class TraceCollector:
    """Collects tool calls and messages during online scanning."""

    def __init__(self):
        self._tool_calls: list[dict] = []
        self._messages: list[dict] = []

    def clear(self):
        self._tool_calls.clear()
        self._messages.clear()

    def record(self, tool_calls: list[dict], messages: list[dict]):
        """Record tool calls and messages from a single exchange."""
        self._tool_calls.extend(tool_calls)
        self._messages.extend(messages)

    def get_tool_calls(self) -> list[dict]:
        return list(self._tool_calls)

    def get_trace(self) -> list[dict]:
        return list(self._messages)


class ScanEngine:
    """Orchestrates security scanning in online or offline mode."""

    def __init__(self, offline_mode: bool = False):
        self.offline_mode = offline_mode
        self.attacks = list_attacks()

    def run(self, target: str, attack_names: list[str] | None = None,
            template: str | None = None, show_progress: bool = True) -> list[AttackResult]:
        """Run attacks. Auto-detects mode based on target format.

        Online targets (any spec that resolve_target understands):
          - 'hermes'                  → Hermes full agent (slow, real tool exec)
          - 'hermes-fast'             → Direct API via Hermes config (fast, simulated tools)
          - 'openai:gpt-4o'           → OpenAI API
          - 'openrouter:x/model'      → OpenRouter API
          - 'deepseek:deepseek-v4'    → DeepSeek API
          - 'api:https://url/v1:model'→ Custom endpoint

        Offline targets:
          - 'trace.json' or 'path/to/trace.json' → parse JSON trace file
        """
        start_time = time.monotonic()
        # Check if target is a file-based trace (offline)
        _OFFLINE_EXTS = (".json", ".jsonl", ".ndjson", ".claude.json", ".ls.json", ".trace.json")
        if target.endswith(_OFFLINE_EXTS):
            results = self._run_offline_file(target, attack_names, show_progress=show_progress)
            return ScanResults(results, time.monotonic() - start_time)
        # Also check if it looks like a file path (contains a dot + extension)
        if "/" in target or "\\" in target:
            path = Path(target)
            if path.exists() and path.suffix in {".json", ".jsonl", ".ndjson"}:
                results = self._run_offline_file(target, attack_names, show_progress=show_progress)
                return ScanResults(results, time.monotonic() - start_time)
        try:
            results = self._run_online(target, attack_names, template, show_progress=show_progress)
            return ScanResults(results, time.monotonic() - start_time)
        except Exception as e:
            if target in ("hermes", "hermes-fast"):
                from agentsec.cli import ERR
                ERR.print("[yellow]此 target 需要 Hermes Agent（hermes-agent.nousresearch.com）或 Hermes 配置，跳过[/yellow]")
                ERR.print(f"[dim]{e}[/dim]")
                return ScanResults([], time.monotonic() - start_time)
            raise

    def _run_online(self, target_spec: str,
                    attack_names: list[str] | None = None,
                    template: str | None = None,
                    show_progress: bool = True) -> list[AttackResult]:
        """Run attacks against a live agent."""
        from agentsec.target import resolve_target
        from agentsec.judge import DetectionPipeline

        target = resolve_target(target_spec, template=template)
        results = []
        attacks_to_run = self._select_attacks(attack_names)
        pipeline = DetectionPipeline(use_llm_judge=True)

        try:
            for name, cls in self._progress(attacks_to_run.items(), show_progress):
                instance = cls()
                collector = TraceCollector()

                def make_chat():

                    def chat_fn(msg: str) -> str:
                        response = target.chat(msg)
                        target.get_last_messages()
                        calls = target.get_last_tool_calls()
                        collector.record(calls, target.get_last_messages())
                        return response
                    return chat_fn

                agent_chat = make_chat()

                if hasattr(instance, "run_online"):
                    try:
                        result = instance.run_online(agent_chat, collector)

                        # Evaluate with Detection Pipeline
                        attack_prompt = ""
                        if result.response:
                            try:
                                responses = json.loads(result.response)
                                if isinstance(responses, list) and len(responses) > 0:
                                    attack_prompt = responses[0].get("prompt", "")
                            except (json.JSONDecodeError, TypeError, IndexError):
                                attack_prompt = result.response[:200]

                        verdict = pipeline.evaluate(
                            attack_name=name,
                            attack_prompt=attack_prompt,
                            agent_response=result.response,
                            tool_calls=result.tool_calls,
                            severity=result.severity,
                        )

                        result.exploited = verdict.exploited
                        result.description = verdict.reason
                        result.recommendation = self._recommendation_for(name, verdict.exploited)
                        result.trace = [{"layer": verdict.layer,
                                         "confidence": verdict.confidence,
                                         "evidence": verdict.evidence}]

                    except Exception as e:
                        result = AttackResult(
                            name=name,
                            severity="low",
                            exploited=False,
                            description=f"执行错误: {e}"
                        )
                else:
                    result = AttackResult(
                        name=name, severity="medium", exploited=False,
                        description="此攻击不支持在线模式"
                    )
                results.append(result)

        finally:
            target.close()

        return results

    def run_offline(self, trace: list[dict],
                    attack_names: list[str] | None = None,
                    show_progress: bool = True) -> list[AttackResult]:
        """Run all attacks against an offline trace."""
        results = []
        attacks_to_run = self._select_attacks(attack_names)

        for name, cls in self._progress(attacks_to_run.items(), show_progress):
            try:
                instance = cls()
                if hasattr(instance, "run_offline"):
                    result = instance.run_offline(trace)
                else:
                    result = AttackResult(name=name, severity="medium", exploited=False,
                                          description="此攻击不支持离线模式")
                result.recommendation = self._recommendation_for(name, result.exploited)
                results.append(result)
            except Exception as e:
                results.append(AttackResult(name=name, severity="low", exploited=False,
                                            description=f"执行错误: {e}"))

        return results

    def run_offline_trace(self, trace: list[dict],
                          attack_names: list[str] | None = None) -> list[AttackResult]:
        """Alias for run_offline."""
        return self.run_offline(trace, attack_names)

    def _run_offline_file(self, target: str,
                          attack_names: list[str] | None = None,
                          show_progress: bool = True) -> list[AttackResult]:
        """Parse a trace file and run offline analysis.

        Uses trace_adapters to auto-detect and load various trace formats.
        Supports LangSmith, LangChain, Claude Code, OpenAI, and generic JSON.
        """
        path = Path(target)
        if not path.exists():
            from agentsec.cli import ERR
            ERR.print(f"[red]File not found:[/red] {target}")
            return []

        # Use trace adapters for format detection
        from agentsec.trace_adapters import detect_and_load

        trace = detect_and_load(str(path))
        if not trace:
            # Fall back to raw JSON load for generic .json files
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                trace = data if isinstance(data, list) else data.get("messages", [])
            except (json.JSONDecodeError, UnicodeDecodeError):
                from agentsec.cli import ERR
                ERR.print(f"[red]Unable to parse trace file:[/red] {target}")
                ERR.print("[yellow]Try using one of the supported formats:[/yellow]")
                from agentsec.trace_adapters import list_supported_formats
                for name, desc in list_supported_formats().items():
                    ERR.print(f"  [cyan]{name}[/cyan]: {desc}")
                return []

        if not trace:
            from agentsec.cli import ERR
            ERR.print(f"[yellow]No messages found in:[/yellow] {target}")
            return []

        return self.run_offline(trace, attack_names, show_progress=show_progress)

    def _select_attacks(self, names: list[str] | None) -> dict:
        """Filter attacks by name. None = all."""
        if not names:
            return dict(self.attacks)
        return {n: self.attacks[n] for n in names if n in self.attacks}

    def _progress(self, items, show_progress: bool):
        items = list(items)
        if not show_progress:
            return items
        try:
            from tqdm import tqdm
            return tqdm(items, desc="Scanning")
        except Exception:
            return items

    def _recommendation_for(self, attack_name: str, exploited: bool) -> str:
        if not exploited:
            return ""
        try:
            from agentsec.judge import ToolCallAnalyzer
            return ToolCallAnalyzer.fix_advice(attack_name)
        except Exception:
            return ""


def load_trace_from_session(session_id: str,
                            db_path: str | None = None) -> list[dict]:
    """Load a conversation trace from Hermes state.db by session ID."""
    import sqlite3
    from pathlib import Path

    if not db_path:
        db_path = str(Path.home() / ".hermes" / "state.db")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT role, content, tool_calls, timestamp
        FROM messages
        WHERE session_id = ?
        ORDER BY timestamp ASC
    """, (session_id,)).fetchall()
    conn.close()

    trace = []
    for r in rows:
        entry = {"role": r["role"], "content": r["content"] or ""}
        if r["tool_calls"]:
            try:
                entry["tool_calls"] = json.loads(r["tool_calls"])
            except (json.JSONDecodeError, TypeError):
                pass
        trace.append(entry)
    return trace
