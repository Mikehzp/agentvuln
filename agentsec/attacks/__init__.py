"""Attack templates package."""
from agentsec.attacks.base import AttackResult

# Import attack modules to trigger @register decorators
from agentsec.attacks import tool_injection
from agentsec.attacks import indirect_injection
from agentsec.attacks import privilege_escalation
from agentsec.attacks import tool_chain
from agentsec.attacks import memory_poisoning
from agentsec.attacks import system_prompt_leak
from agentsec.attacks import data_leak
from agentsec.attacks import dos_attack
from agentsec.attacks import context_overflow
from agentsec.attacks import hallucination_trigger
from agentsec.attacks import mcp_security
from agentsec.attacks import credential_hijacking
from agentsec.attacks import agent_to_agent
from agentsec.attacks import tool_confusion
from agentsec.attacks import rag_poisoning
from agentsec.attacks import cross_session_memory
from agentsec.attacks import multi_agent_collusion
from agentsec.attacks import tool_output_manipulation
