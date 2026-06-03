"""Scan profiles — pre-defined attack sets for common use cases."""

from agentsec.registry import list_attacks

PROFILES = {
    "quick": [
        "tool_argument_injection",
        "privilege_escalation",
        "credential_hijacking",
        "mcp_protocol_security",
        "system_prompt_leak",
    ],
    "daily": [
        "tool_argument_injection",
        "privilege_escalation",
        "rag_poisoning",
        "tool_output_manipulation",
        "system_prompt_leak",
        "data_leak",
        "credential_hijacking",
        "multi_agent_collusion",
    ],
    "full": None,  # All attacks
}


def resolve_profile(name: str) -> list[str] | None:
    """Resolve a profile name to a list of attack names. Returns None for 'full'."""
    return PROFILES.get(name)


def list_profiles() -> list[str]:
    """List available profile names."""
    return list(PROFILES.keys())
