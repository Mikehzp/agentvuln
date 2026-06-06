"""Interactive shell — manually probe an agent and observe tool calls in real time."""

import json
import shlex
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
from rich.markup import escape
from rich import box

from agentsec.registry import list_attacks

console = Console()
ERR = Console(stderr=True)


def parse_shell_command(user_input: str) -> tuple[str, list[str]] | None:
    """Parse slash commands used by the interactive shell."""
    text = user_input.strip()
    if not text.startswith("/"):
        return None
    cmd, *args = shlex.split(text)
    return cmd.lower(), args


def cmd_shell(target: str, system_prompt: str | None = None):
    """Open an interactive probe shell against a target agent."""

    # ── Initialize target ──────────────────────────────────────
    try:
        from agentsec.target import resolve_target
        agent = resolve_target(target)
        console.print(Panel(f"[bold]🧪 Agent Security Shell[/bold]\n"
                            f"[dim]Target: {escape(target)} | "
                            f"Model: {agent.model}[/dim]"))
    except Exception as e:
        ERR.print(f"[red]Failed to initialize target: {e}[/red]")
        return 1

    console.print()
    console.print("[dim]Type a prompt to send to the agent. "
                  "Slash commands:[/dim]")
    console.print("  [bold]/help[/bold]         — Show this help")
    console.print("  [bold]/attacks[/bold]      — List available attacks")
    console.print("  [bold]/run <name>[/bold]   — Run a registered attack")
    console.print("  [bold]/system <text>[/bold]— Override system prompt")
    console.print("  [bold]/save <file>[/bold]  — Save session to JSON")
    console.print("  [bold]/clear[/bold]        — Clear chat history")
    console.print("  [bold]/quit[/bold]         — Exit shell")
    console.print()

    # ── Session state ─────────────────────────────────────────
    session_history: list[dict] = []
    attacks = list_attacks()

    # ── REPL loop ──────────────────────────────────────────────
    while True:
        try:
            user_input = input("⟩ ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not user_input:
            continue

        # ── Slash commands ──────────────────────────────────
        if user_input.startswith("/"):
            cmd, args = parse_shell_command(user_input)

            if cmd == "/quit" or cmd == "/exit":
                break

            elif cmd == "/help":
                console.print("[bold]Slash Commands:[/bold]")
                console.print("  [bold]/help[/bold]         — This help")
                console.print("  [bold]/attacks[/bold]      — List all registered attacks")
                console.print("  [bold]/run <name>[/bold]   — Run a registered attack")
                console.print("  [bold]/system <text>[/bold]— Set system prompt")
                console.print("  [bold]/save <file>[/bold]  — Save session trace")
                console.print("  [bold]/clear[/bold]        — Clear conversation")
                console.print("  [bold]/quit[/bold]         — Exit")
                continue

            elif cmd == "/attacks":
                table = Table(title=f"Available Attacks ({len(attacks)})",
                              box=box.ROUNDED)
                table.add_column("Name", style="cyan")
                table.add_column("Severity")
                table.add_column("Description")
                for name, cls in sorted(attacks.items()):
                    sev = getattr(cls, "severity", "medium")
                    sev_tag = {"critical": "[red]CRITICAL[/red]",
                               "high": "[yellow]HIGH[/yellow]",
                               "medium": "[magenta]MEDIUM[/magenta]",
                               "low": "[cyan]LOW[/cyan]"}.get(sev, sev)
                    desc = getattr(cls, "description", "")[:60]
                    table.add_row(name, sev_tag, desc)
                console.print(table)
                continue

            elif cmd == "/run" and args:
                attack_name = args[0]
                if attack_name not in attacks:
                    ERR.print(f"[red]Unknown attack: {attack_name}[/red]")
                    continue
                cls = attacks[attack_name]
                instance = cls()
                if not hasattr(instance, "run_online"):
                    ERR.print(f"[yellow]Attack '{attack_name}' has no online mode[/yellow]")
                    continue

                console.print(f"[bold]⚡ Running attack:[/bold] {attack_name}")
                console.print()

                # Monkey-patch: we build a mini chat function
                class MiniCollector:
                    def __init__(self):
                        self._calls = []
                        self._msgs = []
                    def clear(self): self._calls = []; self._msgs = []
                    def record(self, calls, msgs): self._calls.extend(calls); self._msgs.extend(msgs)
                    def get_tool_calls(self): return list(self._calls)
                    def get_trace(self): return list(self._msgs)

                collector = MiniCollector()

                def chat_fn(msg: str) -> str:
                    resp = agent.chat(msg)
                    agent.get_last_messages()
                    calls = agent.get_last_tool_calls()
                    collector.record(calls, agent.get_last_messages())
                    return resp

                try:
                    result = instance.run_online(chat_fn, collector)
                    # Save to session
                    session_history.append({
                        "type": "attack_run",
                        "attack": attack_name,
                        "result": {
                            "exploited": result.exploited,
                            "severity": result.severity,
                            "description": result.description[:200],
                        }
                    })
                except Exception as e:
                    ERR.print(f"[red]Attack failed: {e}[/red]")
                    continue

                # Show summary
                tag = "[red]🔴 VULN[/red]" if result.exploited else "[green]✅ PASS[/green]"
                console.print()
                console.print(f"  {tag}  [bold]{result.name}[/bold]")
                console.print(f"       {result.description[:200]}")
                console.print()

                # Show tool calls from collector
                calls = collector.get_tool_calls()
                if calls:
                    _show_tool_calls(calls)
                continue

            elif cmd == "/system":
                new_prompt = " ".join(args) if args else ""
                if new_prompt:
                    agent._system_prompt_override = new_prompt
                    console.print(f"[green]✅ System prompt updated[/green]")
                else:
                    agent._system_prompt_override = None
                    console.print("[dim]System prompt reset to default[/dim]")
                continue

            elif cmd == "/save" and args:
                filepath = args[0]
                data = {
                    "target": target,
                    "model": getattr(agent, "_model", "?"),
                    "timestamp": datetime.now().isoformat(),
                    "messages": session_history,
                }
                Path(filepath).write_text(json.dumps(data, indent=2, ensure_ascii=False))
                console.print(f"[green]✅ Session saved to {filepath}[/green]")
                continue

            elif cmd == "/clear":
                session_history.clear()
                console.print("[dim]Session history cleared[/dim]")
                continue

            else:
                ERR.print(f"[yellow]Unknown command: {cmd}. Try /help[/yellow]")
                continue

        # ── Send prompt to agent ──────────────────────────
        try:
            console.print("[dim]Sending...[/dim]")
            response = agent.chat(user_input)
            calls = agent.get_last_tool_calls()
            messages = agent.get_last_messages()

            # Save to session
            entry = {
                "type": "probe",
                "prompt": user_input,
                "response": response[:500],
                "tool_calls": calls,
                "timestamp": datetime.now().isoformat(),
            }
            session_history.append(entry)

            # Show response
            console.print()
            console.print(Panel(
                Syntax(response, "text", word_wrap=True, theme="monokai", line_numbers=False),
                title="[bold]🤖 Agent Response[/bold]",
                border_style="green",
            ))

            # Show tool calls if any
            _show_tool_calls(calls)

            # Show message count in session
            console.print(f"[dim]Session: {len(session_history)} exchanges[/dim]")
            console.print()

        except Exception as e:
            ERR.print(f"[red]Error: {e}[/red]")

    # ── Cleanup ────────────────────────────────────────────────
    agent.close()
    console.print("[dim]Shell closed.[/dim]")

    # If session has content, offer to save
    if session_history:
        console.print()
        console.print(f"[dim]Session has {len(session_history)} exchanges.[/dim]")
        console.print(f"[dim]Use /save <file> to save, or they will be discarded.[/dim]")

    return 0


def _show_tool_calls(calls: list[dict]):
    """Display tool calls as a rich table."""
    if not calls:
        return

    table = Table(title="Tool Calls", box=box.SQUARE, title_justify="left")
    table.add_column("#", style="dim")
    table.add_column("Function", style="cyan")
    table.add_column("Arguments", style="white")

    for i, call in enumerate(calls, 1):
        fn_data = call.get("function", "?")
        fn = fn_data if isinstance(fn_data, str) else fn_data.get("name", "?") if isinstance(fn_data, dict) else "?"
        args = call.get("arguments", {})
        if isinstance(args, dict):
            args_str = json.dumps(args, ensure_ascii=False)[:200]
        else:
            args_str = str(args)[:200]
        table.add_row(str(i), fn, escape(args_str))

    console.print(table)
    console.print()
