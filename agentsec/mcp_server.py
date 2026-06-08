"""agentvuln MCP Server — expose security scanning as MCP tools for any MCP client."""

from __future__ import annotations

import json
from typing import Optional

from mcp.server import FastMCP

from agentsec.engine import ScanEngine
from agentsec.registry import list_attacks as _list_registered_attacks

server = FastMCP(
    "agentvuln",
    instructions="""AI Agent Security Scanner — test AI agents against 18+ tool-calling vulnerabilities.

## Quick Start
1. Scan a live agent: `scan_agent(target="deepseek:deepseek-v4-flash", profile="quick")`
2. Check a trace file: `scan_trace(trace_path="/path/to/trace.json")`
3. Discover what's available: `list_attacks()`, `list_profiles()`, `list_templates()`

## Target Formats
- `deepseek:deepseek-v4-flash` — known provider + model
- `openai:gpt-4o` — OpenAI
- `openrouter:anthropic/claude-sonnet-4` — OpenRouter
- `hermes-fast` — Direct API (uses Hermes config)
- `hermes` — Full Hermes agent loop (slow, deep)
- `api:https://url/v1:model` — Custom OpenAI-compatible endpoint

API keys are read from environment variables (e.g. DEEPSEEK_API_KEY, OPENAI_API_KEY).
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

    Supports online scanning against any OpenAI-compatible API.
    API keys must be set in environment variables (DEEPSEEK_API_KEY, OPENAI_API_KEY, etc.).

    Args:
        target: Target specification (e.g. 'deepseek:deepseek-v4-flash', 'openai:gpt-4o',
                'hermes-fast', 'api:https://url/v1:model')
        profile: Scan profile — 'quick' (5 attacks), 'daily' (8 attacks), 'full' (all 18)
        template: Optional agent simulation template name (from `list_templates()`)
        attacks: Optional comma-separated list of specific attack names to run (overrides profile)

    Returns:
        JSON string with scan results including per-attack findings and summary.
    """
    engine = ScanEngine()

    # Resolve attack names from profile or explicit list
    attack_names: list[str] | None = None
    if attacks:
        attack_names = [a.strip() for a in attacks.split(",") if a.strip()]
    elif profile and profile != "full":
        from agentsec.profiles import resolve_profile
        attack_names = resolve_profile(profile)

    results = engine.run(target, attack_names, template=template, show_progress=False)
    duration = getattr(results, "duration_seconds", 0.0)

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
            result[name] = {"attack_count": len(attacks), "attacks": attacks}

    return json.dumps(result, indent=2, ensure_ascii=False)


@server.tool()
def list_templates() -> str:
    """List available agent simulation templates from the template marketplace.

    Templates simulate specific agent frameworks (LangChain, Claude Code, etc.)
    to test how different architectures respond to attacks.

    Returns:
        JSON string with template metadata (name, description, version, author).
    """
    try:
        from agentsec.template_market import _ensure_dirs, INSTALLED_DIR
        _ensure_dirs()
        templates = []
        for path in sorted(INSTALLED_DIR.glob("*.yaml")):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    import yaml
                    data = yaml.safe_load(f)
                    if isinstance(data, dict):
                        templates.append({
                            "name": data.get("name", path.stem),
                            "severity": data.get("severity", ""),
                            "description": data.get("description", ""),
                            "path": str(path),
                        })
            except Exception:
                templates.append({
                    "name": path.stem,
                    "severity": "?",
                    "description": "Unable to parse",
                    "path": str(path),
                })
        return json.dumps(templates, indent=2, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"error": f"Failed to list templates: {e}"}, indent=2)


@server.tool()
def get_version() -> str:
    """Get the installed agentvuln/agentsec version."""
    from agentsec import __version__
    return json.dumps({"version": __version__, "tool": "agentvuln-mcp"})


def main():
    """Run the MCP server over stdio transport."""
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
