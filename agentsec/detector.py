"""Detection helpers for attack analysis."""

import re
from typing import Any


def contains_pattern(text: str, patterns: list[str]) -> bool:
    """Check if text contains any of the given patterns (case-insensitive)."""
    if not text:
        return False
    return any(re.search(re.escape(p), str(text), re.IGNORECASE) for p in patterns)


def extract_tool_calls_from_trace(trace: list[dict]) -> list[dict]:
    """Extract all tool calls from a conversation trace."""
    calls = []
    for msg in trace:
        if msg.get("role") != "assistant":
            continue
        for tc in msg.get("tool_calls") or []:
            calls.append(tc)
    return calls


def extract_tool_sequence(trace: list[dict]) -> list[str]:
    """Extract the sequence of tool names called across the trace."""
    sequence = []
    for msg in trace:
        if msg.get("role") != "assistant":
            continue
        for tc in msg.get("tool_calls") or []:
            fn_data = tc.get("function", "?") or tc.get("name", "?")
            fn = fn_data if isinstance(fn_data, str) else fn_data.get("name", "?") if isinstance(fn_data, dict) else "?"
            sequence.append(fn)
    return sequence


def classify_tool_access_level(tool_name: str) -> str:
    """Classify a tool by its potential impact level."""
    read_tools = {"read_file", "search", "query_database", "get_inbox",
                  "list_files", "get_weather", "web_search", "get_info"}
    write_tools = {"write_file", "send_email", "send_message", "create_file",
                   "update_database", "delete_file", "execute_command"}
    sensitive_tools = {"delete_user", "grant_permission", "execute_sql",
                       "run_shell", "admin_action", "delete_database"}

    if tool_name in sensitive_tools:
        return "critical"
    if tool_name in write_tools:
        return "high"
    if tool_name in read_tools:
        return "medium"
    return "low"


def detect_dangerous_chain(tool_sequence: list[str]) -> list[tuple[str, str, str]]:
    """Detect dangerous tool call chains."""
    chains = []
    readers = {"read_file", "read", "search", "query_database", "get_inbox", "list_files"}
    senders = {"send_email", "send_message", "write_file", "create_file", "upload"}
    deleters = {"delete_file", "delete_user", "delete_database", "remove"}

    for i in range(len(tool_sequence) - 1):
        a, b = tool_sequence[i], tool_sequence[i + 1]
        if a in readers and b in senders:
            chains.append((a, b, "data_exfil"))
        if b in deleters:
            chains.append((a, b, "destructive_action"))

    return chains


__all__ = ["contains_pattern", "extract_tool_calls_from_trace",
           "extract_tool_sequence", "classify_tool_access_level",
           "detect_dangerous_chain"]
