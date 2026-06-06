"""Attack result data model."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AttackResult:
    """Result of running a single attack against an agent."""

    name: str
    severity: str  # critical, high, medium, low
    exploited: bool
    description: str = ""
    prompt: str = ""
    response: str = ""
    tool_calls: list[dict] = field(default_factory=list)
    trace: list[dict] = field(default_factory=list)
    remediation: str = ""
    risk: str = ""
    recommendation: str = ""
