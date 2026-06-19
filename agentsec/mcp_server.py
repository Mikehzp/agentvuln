"""agentvuln MCP Server â€” expose security scanning as MCP tools for any MCP client."""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from mcp.server import FastMCP

from agentsec.engine import ScanEngine, ScanResults
from agentsec.registry import list_attacks as _list_registered_attacks

server = FastMCP(
    "agentvuln",
    instructions="""AI Agent Security Scanner â€” scan AI agents for tool-calling vulnerabilities.

## Example Usage

"Scan the DeepSeek V4 agent with a quick profile"
â†’ Runs 5 critical attacks, ~30s

"Run a full security scan on openai:gpt-4o"
â†’ Runs all 18 attacks in parallel, ~2min

"Check this trace file for vulnerabilities"
â†’ Scans an offline agent conversation log

"Show me what attacks are available"
â†’ Lists all 18 attack types with severity

## Available Profiles
- quick  â€” 5 attacks, ~30s (fast sanity check)
- daily  â€” 8 attacks, ~2min (routine scan)
- full   â€” all 18 attacks, ~2min (comprehensive)

Just say what you want naturally â€” the agent will call the right tool.
""",
)


def _attack_to_dict(name: str, cls: type) -> dict:
    """Extract attack metadata from an attack class."""
    try:
        inst = cls()
        return {
            "name": getattr(inst, "name", name),
            "description": getattr(inst, "description", ""),
            "severity": getattr(inst, "severity", "medium"),
            "risk": getattr(inst, "risk", ""),
        }
    except Exception as e:
        return {"name": name, "description": f"(error: {e})", "severity": "medium", "risk": ""}


def _result_to_dict(r) -> dict:
    """Serialize a single AttackResult to a JSON-safe dict."""
    return {
        "name": r.name,
        "severity": r.severity,
        "exploited": r.exploited,
        "description": r.description,
        "recommendation": r.recommendation,
        "remediation": r.remediation,
        "trace": r.trace if r.trace else [],
    }


@server.tool()
def scan_agent(
    target: str,
    profile: str = "quick",
    template: Optional[str] = None,
    attacks: Optional[str] = None,
) -> str:
    """Run a security scan against a live AI agent target.

    Profiles:
      quick â€” 5 critical attacks, ~30s (fast sanity check)
      daily â€” 8 attacks, ~2min (routine scan)
      full  â€” all 18 attacks, ~2min (comprehensive)

    Targets: deepseek:deepseek-v4-flash, openai:gpt-4o,
    openrouter:..., hermes-fast, api:https://url/v1:model

    API keys read from env vars (DEEPSEEK_API_KEY, OPENAI_API_KEY, etc.).

    Args:
        target: Target specification (e.g. 'deepseek:deepseek-v4-flash', 'openai:gpt-4o',
                'hermes-fast', 'api:https://url/v1:model')
        profile: Scan profile - 'quick' (5 attacks), 'daily' (8 attacks), 'full' (all 18)
        template: Optional agent simulation template name (from `list_templates()`)
        attacks: Optional comma-separated list of specific attack names to run (overrides profile)

    Returns:
        JSON string with scan results including per-attack findings and summary.
    """
    start_time = time.monotonic()

    # Resolve attack names from profile or explicit list
    attack_names: list[str] | None = None
    if attacks:
        attack_names = [a.strip() for a in attacks.split(",") if a.strip()]
    elif profile and profile != "full":
        from agentsec.profiles import resolve_profile
        attack_names = resolve_profile(profile)

    # Small profiles: single-threaded (less overhead)
    if attack_names is not None and len(attack_names) <= 8:
        engine = ScanEngine()
        results = engine.run(target, attack_names, template=template, show_progress=False)

    # Full scan: parallel chunks, each with own engine + target
    else:
        all_attacks = list(_list_registered_attacks().keys())
        names_to_run = attack_names if attack_names is not None else all_attacks

        # Split into 4 chunks for ~4x speedup
        chunk_size = max(1, len(names_to_run) // 4)
        chunks = [names_to_run[i:i + chunk_size] for i in range(0, len(names_to_run), chunk_size)]

        def _run_chunk(chunk: list[str]) -> list:
            eng = ScanEngine()
            eng_results = eng.run(target, chunk, template=template, show_progress=False)
            return list(eng_results)

        with ThreadPoolExecutor(max_workers=len(chunks)) as pool:
            futures = [pool.submit(_run_chunk, chunk) for chunk in chunks]
            all_results: list = []
            for f in as_completed(futures):
                all_results.extend(f.result())

        duration = time.monotonic() - start_time
        results = ScanResults(all_results, duration)

    duration = getattr(results, "duration_seconds", time.monotonic() - start_time)

    summary = {
        "target": target,
        "profile": profile if not attacks else "custom",
        "duration_seconds": round(duration, 2),
        "total": len(results),
        "exploited": sum(1 for r in results if r.exploited),
        "passed": sum(1 for r in results if not r.exploited),
        "findings": [_result_to_dict(r) for r in results],
    }

    return json.dumps(summary, indent=2, ensure_ascii=False)


@server.tool()
def scan_trace(
    trace_path: str,
    attacks: Optional[str] = None,
) -> str:
    """Run a security scan against an offline agent conversation trace file.

    Supports LangSmith, LangChain, Claude Code, OpenAI, and generic JSON trace formats.
    File format is auto-detected.

    Args:
        trace_path: Path to the trace file (.json, .jsonl, .ndjson, .claude.json, etc.)
        attacks: Optional comma-separated list of specific attack names to run.
                 Defaults to all attacks.

    Returns:
        JSON string with scan results for the offline trace.
    """
    engine = ScanEngine(offline_mode=True)

    attack_names: list[str] | None = None
    if attacks:
        attack_names = [a.strip() for a in attacks.split(",") if a.strip()]

    results = engine.run(trace_path, attack_names, show_progress=False)
    duration = getattr(results, "duration_seconds", 0.0)

    summary = {
        "trace_path": trace_path,
        "duration_seconds": round(duration, 2),
        "total": len(results),
        "exploited": sum(1 for r in results if r.exploited),
        "passed": sum(1 for r in results if not r.exploited),
        "findings": [_result_to_dict(r) for r in results],
    }

    return json.dumps(summary, indent=2, ensure_ascii=False)


@server.tool()
def list_attacks() -> str:
    """List all registered security attack types with metadata.

    Returns a JSON array of attacks including name, severity, and description
    for each of the 18+ supported vulnerability types.

    Returns:
        JSON string with all available attacks.
    """
    all_attacks = _list_registered_attacks()
    entries = [_attack_to_dict(name, cls) for name, cls in all_attacks.items()]
    return json.dumps(entries, indent=2, ensure_ascii=False)


@server.tool()
def list_profiles() -> str:
    """List available scan profiles and the attacks they include.

    Profiles are pre-configured attack sets for common use cases:
    - quick: Fast 5-attack sanity check
    - daily: Deeper 8-attack routine scan
    - full: All attacks

    Returns:
        JSON string with profile definitions.
    """
    from agentsec.profiles import PROFILES

    result = {}
    all_attack_names = list(_list_registered_attacks().keys())
    for name, attacks in PROFILES.items():
        if attacks is None:
            result[name] = {"attack_count": len(all_attack_names), "attacks": all_attack_names}
        else:
            result[name] = {"atvGF6·2’Â&GF6·2#¢GF6·7Ğ ¢&WGW&â§6öâæGV×2‡&W7VÇBÂ–æFVçCÓ"ÂVç7W&Uö66–“ÔfÇ6R  ¤6W'fW"çFööÂ‚¦FVbÆ—7E÷FV×ÆFW2‚’Óâ7G# ¢""$Æ—7Bf–Æ&ÆRvVçB6–×VÆF–öâFV×ÆFW2g&öÒF†RFV×ÆFRÖ&¶WGÆ6Rà ¢FV×ÆFW26–×VÆFR7V6–f–2vVçBg&ÖWv÷&·2„Ææt6†–âÂ6ÆVFR6öFRÂWF2â¢FòFW7B†÷rF–ffW&VçB&6†—FV7GW&W2&W7öæBFòGF6·2à ¢&WGW&ç3 ¢¥4ôâ7G&–ærv—F‚FV×ÆFRÖWFFF†æÖRÂFW67&—F–öâÂfW'6–öâÂWF†÷"’à¢"" ¢G'“ ¢g&öÒvVçG6V2çFV×ÆFUöÖ&¶WB–×÷'BöVç7W&UöF—'2Â”å5DÄÄTEôD• ¢öVç7W&UöF—'2‚¢FV×ÆFW2ÒµĞ¢f÷"F‚–â6÷'FVB„”å5DÄÄTEôD•"ævÆö"‚"¢ç–ÖÂ"’“ ¢G'“ ¢v—F‚÷Vâ‡F‚Â'""ÂVæ6öF–æsÒ'WFbÓ‚"’2c ¢–×÷'B–ÖÀ¢FFÒ–ÖÂç6fUöÆöB†b¢–b—6–ç7Fæ6R†FFÂF–7B“ ¢FV×ÆFW2æVæB‡°¢&æÖR#¢FFævWB‚&æÖR"ÂF‚ç7FVÒ’À¢'6WfW&—G’#¢FFævWB‚'6WfW&—G’"Â""’À¢&FW67&—F–öâ#¢FFævWB‚&FW67&—F–öâ"Â""’À¢'F‚#¢7G"‡F‚’À¢Ò¢W†6WBW†6WF–öã ¢FV×ÆFW2æVæB‡°¢&æÖR#¢F‚ç7FVÒÀ¢'6WfW&—G’#¢#ò"À¢&FW67&—F–öâ#¢%Væ&ÆRFò'6R"À¢'F‚#¢7G"‡F‚’À¢Ò¢&WGW&â§6öâæGV×2‡FV×ÆFW2Â–æFVçCÓ"ÂVç7W&Uö66–“ÔfÇ6R¢W†6WBW†6WF–öâ2S ¢&WGW&â§6öâæGV×2‡²&W'


@server.tool()
def get_version() -> str:
    """Get the installed agentvuln/agentsec version."""
    from agentsec import __version__
    return json.dumps({"veuõ÷fW'6–öåõòÂ'FööÂ#¢&vVçGgVÆâÖÖ7'Ò  ¦FVbÖ–â‚“ ¢""%'VâF†RÔ56W'fW"÷fW"7FF–òG&ç7÷'Bâ"" ¢6W'fW"ç'Vâ‡G&ç7÷'CÒ'7FF–ò"  ¦–bõöæÖUõòÓÒ%õöÖ–åõò# ¢Ö–â‚ 