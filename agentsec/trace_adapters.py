"""Offline trace format adapters for common agent frameworks.

Converts traces from various agent frameworks into a standardized format:
    {"role": str, "content": str, optional "tool_calls": [{"function": str, "arguments": dict}]}

Supported formats:
  - LangChain / LangSmith (JSON export)
  - Claude Code conversation logs
  - OpenAI chat completion messages format
  - Generic JSON traces
"""

import json
from pathlib import Path
from typing import Any


# ── Standardized format constants ──────────────────────────────────────────

STANDARD_KEYS = {"role", "content", "tool_calls"}


def _normalize_message(msg: dict) -> dict:
    """Ensure a message dict has at least 'role' and 'content'."""
    return {
        "role": msg.get("role", "unknown"),
        "content": msg.get("content", "") or "",
        "tool_calls": msg.get("tool_calls", []),
    }


def _normalize_tool_call(tc: dict) -> dict:
    """Normalize a tool_call dict to {'function': str, 'arguments': dict}."""
    # OpenAI-style: {"id": "...", "function": {"name": "...", "arguments": "..."}}
    # Anthropic-style: {"name": "...", "input": {...}}
    # LangChain-style: {"name": "...", "args": {...}}
    if "function" in tc:
        func = tc["function"]
        name = func.get("name", "")
        args = func.get("arguments", {})
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except (json.JSONDecodeError, TypeError):
                args = {"raw": args}
    elif "name" in tc and "input" in tc:
        name = tc["name"]
        args = tc["input"]
    elif "name" in tc and "args" in tc:
        name = tc["name"]
        args = tc["args"]
    elif "name" in tc:
        name = tc["name"]
        args = {k: v for k, v in tc.items() if k not in ("name", "id", "type")}
    else:
        name = tc.get("id", "unknown")
        args = dict(tc)
    # Ensure args is a dict
    if not isinstance(args, dict):
        args = {"value": str(args)}
    return {"function": name, "arguments": args}


def _find_standard_messages(data: Any) -> list[dict] | None:
    """Try to extract a list of standard {role, content, tool_calls} messages.

    Returns None if data doesn't look like a standard trace.
    """
    if isinstance(data, list):
        if all(isinstance(m, dict) and "role" in m for m in data):
            trace = []
            for m in data:
                entry = _normalize_message(m)
                if entry["tool_calls"] and isinstance(entry["tool_calls"], list):
                    entry["tool_calls"] = [
                        _normalize_tool_call(tc) for tc in entry["tool_calls"]
                    ]
                trace.append(entry)
            return trace
    return None


# ── LangSmith Trace Loader ────────────────────────────────────────────────


def load_langsmith_trace(path: str) -> list[dict]:
    """Load a LangSmith trace export file.

    LangSmith exports contain nested run trees (LLM calls, chain steps, tool calls).
    This flattens the relevant conversation messages into our standardized format.

    Args:
        path: Path to the LangSmith trace JSON file (may be a list of runs
              or a dict with a 'runs' key).

    Returns:
        Standardized trace list, or empty list on failure.
    """
    try:
        data = _read_json(path)
        if data is None:
            return []
    except Exception:
        return []

    # LangSmith can export as a dict with top-level keys
    if isinstance(data, dict):
        # Try 'runs' key
        runs = data.get("runs", data.get("data", None))
        if runs is None:
            runs = data.get("traces", None)
        if runs is None:
            runs = [data]  # single run
    elif isinstance(data, list):
        # Already a list of runs (most common for LangSmith exports)
        # But also check if it's already a standard trace
        standard = _find_standard_messages(data)
        if standard is not None:
            return standard
        runs = data
    else:
        return []

    if not isinstance(runs, list):
        runs = [runs]

    return _extract_messages_from_langsmith_runs(runs)


def _extract_messages_from_langsmith_runs(runs: list[dict]) -> list[dict]:
    """Flatten LangSmith run trees into a linear message trace."""
    trace: list[dict] = []

    def _walk(run: dict):
        """Recursively walk a run tree extracting messages."""
        # Extract from LLM runs
        if run.get("run_type") == "llm" or run.get("type") == "llm":
            msgs = _extract_llm_run_messages(run)
            trace.extend(msgs)

        # Extract from chain runs that carry messages directly
        if run.get("run_type") in ("chain", "tool", None) or run.get("type") in (
            "chain",
            "tool",
            None,
        ):
            msgs = _extract_run_io_messages(run)
            trace.extend(msgs)

        # Recurse into child runs
        for child in run.get("child_runs", run.get("children", [])):
            if isinstance(child, dict):
                _walk(child)

        # Also recurse into child_llm_runs / child_tool_runs if present
        for child_key in ("child_llm_runs", "child_tool_runs", "child_chain_runs"):
            for child in run.get(child_key, []):
                if isinstance(child, dict):
                    _walk(child)

    for run in runs:
        if isinstance(run, dict):
            _walk(run)

    # De-duplicate adjacent messages from the same role (LangSmith nesting can
    # produce duplicates)
    deduped: list[dict] = []
    for m in trace:
        if deduped and deduped[-1]["role"] == m["role"] and deduped[-1]["content"] == m["content"]:
            # Merge tool_calls if present
            if m.get("tool_calls") and not deduped[-1].get("tool_calls"):
                deduped[-1]["tool_calls"] = m["tool_calls"]
            continue
        deduped.append(m)

    return deduped


def _extract_llm_run_messages(run: dict) -> list[dict]:
    """Extract messages from an LLM run."""
    messages: list[dict] = []

    inputs = run.get("inputs", {})
    outputs = run.get("outputs", {})

    # LangSmith stores prompts as messages or string
    prompt_messages = inputs.get("messages", inputs.get("prompts", []))
    if isinstance(prompt_messages, str):
        # Single string prompt → wrap as user message
        messages.append({"role": "user", "content": prompt_messages, "tool_calls": []})
    elif isinstance(prompt_messages, list):
        for msg in prompt_messages:
            if isinstance(msg, dict):
                entry = _normalize_message(msg)
                # Convert OpenAI-style tool_calls
                if entry["tool_calls"] and isinstance(entry["tool_calls"], list):
                    entry["tool_calls"] = [
                        _normalize_tool_call(tc) for tc in entry["tool_calls"]
                    ]
                messages.append(entry)
            elif isinstance(msg, str):
                # Some exports store just message strings
                messages.append({"role": "user", "content": msg, "tool_calls": []})

    # Output generations
    generations = outputs.get("generations", [])
    if isinstance(generations, list):
        for gen in generations:
            if isinstance(gen, dict):
                # Direct message
                if "message" in gen:
                    msg = gen["message"]
                    if isinstance(msg, dict):
                        entry = _normalize_message(msg)
                        if entry["tool_calls"] and isinstance(entry["tool_calls"], list):
                            entry["tool_calls"] = [
                                _normalize_tool_call(tc) for tc in entry["tool_calls"]
                            ]
                        messages.append(entry)
                    elif isinstance(msg, str):
                        messages.append(
                            {"role": "assistant", "content": msg, "tool_calls": []}
                        )
                elif "text" in gen:
                    messages.append(
                        {
                            "role": "assistant",
                            "content": gen["text"],
                            "tool_calls": [],
                        }
                    )
                # LangChain generation with multiple outputs
                if "generations" in gen and isinstance(gen["generations"], list):
                    for sub in gen["generations"]:
                        if isinstance(sub, dict):
                            msg = sub.get("message", sub.get("text", ""))
                            if isinstance(msg, dict):
                                entry = _normalize_message(msg)
                                messages.append(entry)
                            elif isinstance(msg, str):
                                messages.append(
                                    {"role": "assistant", "content": msg, "tool_calls": []}
                                )

    # Direct output message (some newer LangSmith exports)
    output_message = outputs.get("message", None)
    if output_message and isinstance(output_message, dict):
        entry = _normalize_message(output_message)
        messages.append(entry)

    # If outputs has a 'messages' key (OpenAI-style response format)
    if "messages" in outputs and isinstance(outputs["messages"], list):
        for msg in outputs["messages"]:
            if isinstance(msg, dict):
                entry = _normalize_message(msg)
                messages.append(entry)

    return messages


def _extract_run_io_messages(run: dict) -> list[dict]:
    """Extract messages from a chain/tool run's input/output."""
    messages: list[dict] = []
    inputs = run.get("inputs", {})
    outputs = run.get("outputs", {})

    # Check input for message-like content
    for key in ("input", "question", "prompt", "query"):
        val = inputs.get(key, None)
        if val and isinstance(val, str):
            # Avoid adding duplicate if already captured by LLM run
            if not messages or messages[-1].get("content") != val:
                messages.append({"role": "user", "content": val, "tool_calls": []})
            break

    # Check output for message-like content
    for key in ("output", "response", "answer", "result", "text"):
        val = outputs.get(key, None)
        if val and isinstance(val, str):
            if not messages or messages[-1].get("content") != val:
                messages.append(
                    {"role": "assistant", "content": val, "tool_calls": []}
                )
            break

    # Check for tool call output
    if run.get("run_type") == "tool" or run.get("type") == "tool":
        tool_name = run.get("name", "tool")
        output_content = outputs.get("output", outputs.get("result", outputs.get("content", "")))
        if isinstance(output_content, str) and output_content:
            messages.append(
                {
                    "role": "tool",
                    "content": output_content,
                    "tool_calls": [],
                    "_tool_name": tool_name,
                }
            )

    return messages


# ── LangChain Run JSON Loader ─────────────────────────────────────────────


def load_langchain_traces(path: str) -> list[dict]:
    """Load LangChain run JSON (raw Run objects saved to file).

    LangChain's run collector saves runs as JSON arrays. Each run can contain
    inputs, outputs, and child runs. This adapts them to our standard format.

    Args:
        path: Path to a LangChain run JSON file. May contain:
              - A list of Run objects
              - A single Run object
              - A dict with a 'runs' key

    Returns:
        Standardized trace list, or empty list on failure.
    """
    try:
        data = _read_json(path)
        if data is None:
            return []
    except Exception:
        return []

    # Reuse the LangSmith extractor since formats overlap heavily
    if isinstance(data, list):
        standard = _find_standard_messages(data)
        if standard is not None:
            return standard
        runs = data
    elif isinstance(data, dict):
        runs = data.get("runs", data.get("data", [data]))
        if isinstance(runs, dict):
            runs = [runs]
    else:
        return []

    return _extract_messages_from_langsmith_runs(runs)


# ── Claude Code Log Loader ────────────────────────────────────────────────


def load_claude_code_log(path: str) -> list[dict]:
    """Load a Claude Code conversation log.

    Claude Code stores conversations as JSON objects with a 'messages' or
    'chat_messages' array. Each message has a 'role' (user/assistant) and
    'content' which can be a string or list of content blocks.

    Content blocks can be:
      - {"type": "text", "text": "..."}
      - {"type": "tool_use", "name": "...", "input": {...}}
      - {"type": "tool_result", "content": "..."}

    Args:
        path: Path to a Claude Code conversation JSON file. Usually found
              in ~/.claude/logs/ as .json files.

    Returns:
        Standardized trace list, or empty list on failure.
    """
    try:
        data = _read_json(path)
        if data is None:
            return []
    except Exception:
        return []

    # Try to find messages array
    messages = None
    if isinstance(data, list):
        standard = _find_standard_messages(data)
        if standard is not None:
            return standard
        # Claude Code sometimes exports a flat list of messages
        messages = data
    elif isinstance(data, dict):
        # Common Claude Code log structures
        for key in ("messages", "chat_messages", "conversation", "talk"):
            if key in data and isinstance(data[key], list):
                messages = data[key]
                break
        if messages is None and "conversation" in data:
            conv = data["conversation"]
            if isinstance(conv, dict):
                for sub_key in ("messages", "chat_messages"):
                    if sub_key in conv and isinstance(conv[sub_key], list):
                        messages = conv[sub_key]
                        break

    if not messages:
        return []

    trace: list[dict] = []

    for msg in messages:
        if not isinstance(msg, dict):
            continue

        role = msg.get("role", "")
        content = msg.get("content", "")

        if isinstance(content, list):
            # Content blocks format
            text_parts: list[str] = []
            tool_calls: list[dict] = []

            for block in content:
                if not isinstance(block, dict):
                    continue
                block_type = block.get("type", "")
                if block_type == "text":
                    text_parts.append(block.get("text", ""))
                elif block_type == "tool_use":
                    tool_calls.append(
                        _normalize_tool_call(
                            {"name": block.get("name", ""), "input": block.get("input", {})}
                        )
                    )
                elif block_type == "tool_result":
                    result_content = block.get("content", "")
                    if isinstance(result_content, list):
                        result_text = " ".join(
                            cb.get("text", "") for cb in result_content if isinstance(cb, dict)
                        )
                    elif isinstance(result_content, str):
                        result_text = result_content
                    else:
                        result_text = str(result_content) if result_content else ""
                    trace.append(
                        {
                            "role": "tool",
                            "content": result_text,
                            "tool_calls": [],
                            "_tool_use_id": block.get("tool_use_id", ""),
                        }
                    )

            content = "\n".join(text_parts)
            entry: dict = {"role": role, "content": content, "tool_calls": tool_calls}
            trace.append(entry)
        elif isinstance(content, str):
            entry = {"role": role, "content": content, "tool_calls": []}
            if role in ("user", "assistant"):
                # Some Claude logs store tool_use as a top-level field
                tool_uses = msg.get("tool_use", msg.get("tool_calls", None))
                if tool_uses:
                    if isinstance(tool_uses, list):
                        entry["tool_calls"] = [_normalize_tool_call(tc) for tc in tool_uses]
                    elif isinstance(tool_uses, dict):
                        entry["tool_calls"] = [_normalize_tool_call(tool_uses)]
            trace.append(entry)

    return trace


# ── OpenAI Chat Completion Format Loader ──────────────────────────────────


def load_openai_messages(path: str) -> list[dict]:
    """Load a file in OpenAI chat completion messages format.

    Expects either:
      - A dict with a "messages" key containing a list of message objects
      - A list of message objects (role, content, optional tool_calls)
      - A list of dicts each containing "messages" keys (multiple conversations)
      - A JSONL file with one conversation per line

    Message format::
        {"role": "user", "content": "..."}
        {"role": "assistant", "content": "...", "tool_calls": [...]}
        {"role": "tool", "content": "...", "tool_call_id": "..."}

    Args:
        path: Path to the JSON or JSONL file.

    Returns:
        Standardized trace list, or empty list on failure.
    """
    try:
        data = _read_json(path)
        if data is None:
            # Try as JSONL
            return _load_openai_jsonl(path)
    except Exception:
        # Try as JSONL
        return _load_openai_jsonl(path)

    # Already a standard trace list
    if isinstance(data, list):
        standard = _find_standard_messages(data)
        if standard is not None:
            return standard

        # Maybe a list of conversations → merge all messages
        all_msgs: list[dict] = []
        for item in data:
            if isinstance(item, dict):
                if "messages" in item:
                    msgs = item["messages"]
                    if isinstance(msgs, list):
                        for m in msgs:
                            if isinstance(m, dict):
                                all_msgs.append(_normalize_message(m))
        if all_msgs:
            return _process_openai_messages(all_msgs)

        # Maybe a list of message dicts with some non-standard keys
        return _process_openai_messages(data)

    # Dict with messages key
    if isinstance(data, dict):
        # OpenAI batch format: {"custom_id": "...", "body": {"messages": [...]}}
        body = data.get("body", data)
        if isinstance(body, dict):
            messages = body.get("messages", None)
            if messages is not None and isinstance(messages, list):
                return _process_openai_messages(messages)

        # Direct messages key
        messages = data.get("messages", data.get("conversation", None))
        if messages is not None and isinstance(messages, list):
            return _process_openai_messages(messages)

    return []


def _load_openai_jsonl(path: str) -> list[dict]:
    """Load a JSONL file of OpenAI messages."""
    try:
        lines = Path(path).read_text(encoding="utf-8").strip().splitlines()
    except Exception:
        return []

    all_msgs: list[dict] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(entry, dict):
            msgs = entry.get("messages", None)
            if msgs and isinstance(msgs, list):
                for m in msgs:
                    if isinstance(m, dict):
                        all_msgs.append(m)
            elif "role" in entry:
                all_msgs.append(entry)
        elif isinstance(entry, list):
            for m in entry:
                if isinstance(m, dict):
                    all_msgs.append(m)

    return _process_openai_messages(all_msgs) if all_msgs else []


def _process_openai_messages(messages: list[dict]) -> list[dict]:
    """Convert OpenAI message dicts to standardized format."""
    trace: list[dict] = []
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        entry = _normalize_message(msg)

        # OpenAI tool_calls are in the assistant message
        raw_tool_calls = msg.get("tool_calls", msg.get("tool_calls", []))
        if raw_tool_calls and isinstance(raw_tool_calls, list):
            normalized = []
            for tc in raw_tool_calls:
                if isinstance(tc, dict):
                    normalized.append(_normalize_tool_call(tc))
            entry["tool_calls"] = normalized

        trace.append(entry)

    return trace


# ── Auto-Detect and Load ──────────────────────────────────────────────────


# Extension → (detection priority, [loader functions])
# Higher priority = checked first
_FORMAT_REGISTRY: list[tuple[str, str, str, list[str], list]] = [
    # (name, description, extension, content_signatures, loader)
    ("langsmith", "LangSmith trace export (JSON)", ".json",
     ["langsmith", "run_type", "child_runs"], load_langsmith_trace),
    ("langchain", "LangChain run JSON", ".json",
     ["SerializedLangChain", "lc_id", "langchain"], load_langchain_traces),
    ("claude_code", "Claude Code conversation log", ".json",
     ["chat_messages", "claude", "tool_use"], load_claude_code_log),
    ("openai", "OpenAI chat completion messages", ".json",
     ["messages", "tool_calls"], load_openai_messages),
]

# Additional extensions that hint at format
_EXTENSION_MAP = {
    ".jsonl": "openai",   # JSONL is most commonly OpenAI format
    ".ndjson": "openai",
    ".claude.json": "claude_code",
    ".langsmith.json": "langsmith",
    ".ls.json": "langsmith",
    ".trace.json": "auto",  # generic trace
}


def detect_and_load(path: str) -> list[dict]:
    """Auto-detect the trace format and load it.

    Detection strategy:
      1. Check if the file is already in standardized format (role/content/tool_calls).
      2. Match by filename extension/suffix hints.
      3. Match by content signatures (specific keys in the JSON).
      4. Fall back to generic OpenAI messages format.
      5. Return empty list on failure.

    Args:
        path: Path to the trace file.

    Returns:
        Standardized trace list, or empty list if detection/loading fails.
    """
    filepath = Path(path)
    if not filepath.exists():
        return []

    try:
        raw_text = filepath.read_text(encoding="utf-8")
    except Exception:
        return []

    # --- Pass 1: Try direct JSON parse for standard format ---
    try:
        data = _read_json(path)
    except Exception:
        data = None

    if data is not None:
        standard = _find_standard_messages(data)
        if standard is not None:
            return standard

    # --- Pass 2: Check filename for format hints ---
    fname_lower = filepath.name.lower()
    ext = filepath.suffix.lower()

    for suffix_pattern, fmt_name in _EXTENSION_MAP.items():
        if fname_lower.endswith(suffix_pattern):
            if fmt_name != "auto":
                loader = _get_loader_by_name(fmt_name)
                if loader:
                    result = loader(path)
                    if result:
                        return result
            break

    # --- Pass 3: Content-based detection ---
    # Scan top-level JSON keys for format signatures
    if data is not None:
        for name, _desc, _ext, signatures, loader in _FORMAT_REGISTRY:
            if _matches_signatures(data, signatures):
                result = loader(path)
                if result:
                    return result

    # --- Pass 4: Try each format in order ---
    for name, _desc, _ext, _signatures, loader in _FORMAT_REGISTRY:
        try:
            result = loader(path)
            if result:
                return result
        except Exception:
            continue

    # --- Pass 5: Last resort — try as generic JSON with messages key ---
    if data is not None:
        if isinstance(data, dict):
            msgs = data.get("messages", data.get("conversation", None))
            if isinstance(msgs, list):
                return _process_openai_messages(msgs)
        elif isinstance(data, list):
            # Maybe it's already a flat list of messages without 'role' (less strict)
            if all(isinstance(m, dict) for m in data):
                return _process_openai_messages(data)

    return []


def _get_loader_by_name(name: str):
    """Resolve a format name to its loader function."""
    mapping = {
        "langsmith": load_langsmith_trace,
        "langchain": load_langchain_traces,
        "claude_code": load_claude_code_log,
        "openai": load_openai_messages,
    }
    return mapping.get(name)


def _matches_signatures(data: Any, signatures: list[str]) -> bool:
    """Check if data contains any of the signature keys."""
    if isinstance(data, dict):
        data_str = json.dumps(data, ensure_ascii=False)
    elif isinstance(data, list):
        if not data:
            return False
        data_str = json.dumps(data, ensure_ascii=False)
    else:
        return False

    data_lower = data_str.lower()
    for sig in signatures:
        if sig.lower() in data_lower:
            return True
    return False


# ── Format Listing ─────────────────────────────────────────────────────────


def list_supported_formats() -> dict:
    """Return a dict of {format_name: description} for all supported formats.

    Returns:
        dict mapping format identifiers to human-readable descriptions.
    """
    return {
        "langsmith": "LangSmith trace export (JSON) — nested run trees from LangSmith",
        "langchain": "LangChain run JSON — raw Run objects saved to file",
        "claude_code": "Claude Code conversation log — JSON from ~/.claude/logs/",
        "openai": "OpenAI chat completion messages — standard {messages: [...]} format",
        "generic_json": "Generic JSON trace — any file with {role, content} message objects",
    }


# ── Helpers ───────────────────────────────────────────────────────────────


def _read_json(path: str) -> Any | None:
    """Read and parse a JSON file. Returns None on failure."""
    try:
        text = Path(path).read_text(encoding="utf-8")
        return json.loads(text)
    except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError):
        return None


__all__ = [
    "load_langsmith_trace",
    "load_langchain_traces",
    "load_claude_code_log",
    "load_openai_messages",
    "detect_and_load",
    "list_supported_formats",
]
