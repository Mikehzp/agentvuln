"""Agent Security Scanner CLI."""

import sys
import json
from pathlib import Path


def _configure_stdio():
    """Keep Unicode CLI output working on Windows consoles."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


_configure_stdio()

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.markup import escape

import datetime

from agentsec.engine import ScanEngine
from agentsec.report import ReportGenerator
from agentsec import db

console = Console()
ERR = Console(stderr=True)

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _should_fail(results, fail_on: str | None) -> bool:
    """Return True when findings meet the configured failure threshold."""
    threshold = (fail_on or "low").lower()
    if threshold == "none":
        return False
    min_rank = SEVERITY_RANK.get(threshold)
    if min_rank is None:
        ERR.print(f"[red]Unknown fail-on threshold: {fail_on}[/red]")
        ERR.print("Available: none, low, medium, high, critical")
        return True
    return any(
        r.exploited and SEVERITY_RANK.get(str(r.severity).lower(), 1) >= min_rank
        for r in results
    )


def _format_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    minutes, secs = divmod(seconds, 60)
    return f"{minutes}m {secs}s" if minutes else f"{secs}s"


def _scan_json_payload(target: str, results, duration_seconds: float) -> dict:
    return {
        "target": target,
        "duration_seconds": duration_seconds,
        "summary": {
            "total": len(results),
            "passed": sum(1 for r in results if not r.exploited),
            "vulnerable": sum(1 for r in results if r.exploited),
        },
        "findings": [
            {
                "name": r.name,
                "severity": r.severity,
                "exploited": r.exploited,
                "reason": r.description,
                "evidence": (
                    r.trace[0].get("evidence", [])
                    if r.trace and isinstance(r.trace[0], dict)
                    else []
                ),
                "recommendation": getattr(r, "recommendation", ""),
            }
            for r in results
        ],
    }


def _resolve_attack_names(profile: str | None, attacks: str | None):
    if profile:
        from agentsec.profiles import resolve_profile
        return resolve_profile(profile)
    if attacks:
        return [a.strip() for a in attacks.split(",")]
    return None


def _cmd_scan_json(target: str, attacks: str | None = None,
                   profile: str | None = None, template: str | None = None,
                   fail_on: str | None = "low") -> int:
    engine = ScanEngine()
    attack_names = _resolve_attack_names(profile, attacks)
    results = engine.run(target, attack_names, template=template, show_progress=False)
    duration_seconds = getattr(results, "duration_seconds", 0.0)
    print(json.dumps(_scan_json_payload(target, results, duration_seconds), ensure_ascii=False, indent=2))
    return 1 if _should_fail(results, fail_on) else 0


def cmd_scan(target: str, attacks: str | None = None, output: str | None = None,
             fix: bool = False, dry_run: bool = False, profile: str | None = None,
             custom_attacks: str | None = None, template: str | None = None,
             list_templates: bool = False, fail_on: str | None = "low",
             json_output: bool = False):
    """Run security scan against an agent target (online or offline)."""
    if json_output:
        return _cmd_scan_json(target, attacks, profile, template, fail_on)

    # Handle --list-templates
    if list_templates:
        from agentsec.templates import list_templates
        console.print("[bold]Available agent simulation templates:[/bold]")
        console.print()
        for name, desc in list_templates().items():
            console.print(f"  [cyan]{name}[/cyan]")
            console.print(f"       {desc}")
        console.print()
        console.print("[dim]Usage: agentsec scan <target> --template <name>[/dim]")
        return 0

    engine = ScanEngine()

    # Resolve attack filter — profile takes priority, then --attacks, then all
    attack_names = None
    if profile:
        from agentsec.profiles import resolve_profile, list_profiles
        attack_names = resolve_profile(profile)
        if attack_names is None:
            # 'full' profile = all attacks
            attack_names = None
            console.print(f"[dim]Profile: {profile} (all attacks)[/dim]")
        elif not attack_names:
            from agentsec.cli import ERR
            ERR.print(f"[red]Unknown profile: {profile}[/red]")
            ERR.print(f"Available: {', '.join(list_profiles())}")
            return 1
        else:
            console.print(f"[dim]Profile: {profile} ({len(attack_names)} attacks)[/dim]")
    elif attacks:
        attack_names = [a.strip() for a in attacks.split(",")]
    console.print(Panel(f"[bold]🧪 Agent Security Scan[/bold]\n"
                        f"[dim]Target: {escape(target)}[/dim]"))
    console.print()

    # Show target details
    _OFFLINE_EXTS = (".json", ".jsonl", ".ndjson", ".claude.json", ".ls.json", ".trace.json")
    if target.endswith(_OFFLINE_EXTS) or Path(target).suffix in (".json", ".jsonl", ".ndjson"):
        console.print(f"[dim]Mode: offline (trace file)[/dim]")
    else:
        try:
            from agentsec.target import resolve_provider_config
            cfg = resolve_provider_config(target)
            fmt = {"hermes": "Hermes full agent", "hermes-fast": "Hermes (direct API)"}.get(target, target)
            console.print(f"[dim]Provider: {cfg.get('provider', '?')}  |  "
                          f"Model: {cfg.get('model', '?')}[/dim]")
            if template:
                from agentsec.templates import get_template
                tpl_name = template if get_template(template) else "custom file"
                console.print(f"[dim]Template: {tpl_name}[/dim]")
        except Exception:
            pass

    # Load custom YAML attacks if provided
    if custom_attacks:
        from agentsec.yaml_loader import load_custom_attacks
        custom = load_custom_attacks(custom_attacks)
        if custom:
            console.print(f"[green]✅ Loaded {len(custom)} custom attack(s) from {custom_attacks}[/green]")
            engine.attacks.update(custom)
        else:
            console.print(f"[yellow]⚠️ No valid YAML attacks found in {custom_attacks}[/yellow]")

    # Also load from installed template marketplace.
    try:
        from agentsec.template_market import INSTALLED_DIR
        if INSTALLED_DIR.exists():
            from agentsec.yaml_loader import load_custom_attacks
            installed = load_custom_attacks(str(INSTALLED_DIR))
            if installed:
                engine.attacks.update(installed)
                console.print(f"[green]✅ Loaded {len(installed)} installed template(s)[/green]")
    except Exception as e:
        console.print(f"[dim]⚠️ Installed templates skipped: {e}[/dim]")

    results = engine.run(target, attack_names, template=template, show_progress=not json_output)

    # Auto-save results to database
    try:
        target_info = {}
        if not target.endswith((".json", ".jsonl", ".ndjson", ".claude.json", ".ls.json", ".trace.json")):
            try:
                from agentsec.target import resolve_provider_config
                target_info = resolve_provider_config(target)
            except Exception:
                pass
        scan_run_id = db.save_scan_run(
            target=target,
            results=results,
            provider=target_info.get("provider", ""),
            model=target_info.get("model", ""),
            template=template or "",
            duration_seconds=getattr(results, "duration_seconds", 0.0),
        )
    except Exception as e:
        console.print(f"[dim]⚠ DB save skipped: {e}[/dim]")

    # Summary
    passed = sum(1 for r in results if not r.exploited)
    failed = sum(1 for r in results if r.exploited)
    duration_seconds = getattr(results, "duration_seconds", 0.0)
    if json_output:
        print(json.dumps(_scan_json_payload(target, results, duration_seconds), ensure_ascii=False, indent=2))
        return 1 if _should_fail(results, fail_on) else 0
    console.print(f"[bold]Results:[/bold] {len(results)} tests — "
                  f"[green]{passed} passed[/green], [red]{failed} vulnerable[/red]")
    console.print(f"[bold]Duration:[/bold] {_format_duration(duration_seconds)}")
    console.print()

    # Detail
    for r in results:
        tag = "[green]✅ PASS[/green]" if not r.exploited else "[red]🔴 VULN[/red]"
        sev_tag = {"critical": "[red]CRITICAL[/red]", "high": "[yellow]HIGH[/yellow]",
                   "medium": "[magenta]MEDIUM[/magenta]", "low": "[cyan]LOW[/cyan]"}.get(r.severity, r.severity)

        # Show pipeline details if available
        pipeline_info = ""
        if r.trace and isinstance(r.trace, list) and len(r.trace) > 0:
            t = r.trace[0]
            if isinstance(t, dict):
                layer = t.get("layer", "")
                conf = t.get("confidence", "")
                evidence = t.get("evidence", [])
                if evidence:
                    pipe_tag = {"tool_analysis": "🔧", "llm_judge": "🧠", "keyword_fallback": "📝"}.get(layer, "?")
                    pipeline_info = f"  [{pipe_tag} {layer} / {conf}]"
                    if r.exploited:
                        pipeline_info += f"\n       [dim]{escape(evidence[0][:120])}[/dim]"

        console.print(f"  {tag} {sev_tag}  {r.name}{pipeline_info}")
        if r.exploited and not pipeline_info:
            console.print(f"       [dim]{escape(r.description[:120])}[/dim]")
        if r.exploited and getattr(r, "recommendation", ""):
            console.print(f"       [cyan]Recommendation:[/cyan] {escape(r.recommendation[:180])}")
        console.print()

    # Auto-fix
    if failed > 0 and (fix or dry_run):
        from agentsec.fixer import apply_all_fixes

        mode = "[yellow]🔍 DRY RUN[/yellow]" if dry_run else "[green]🔧 APPLYING FIXES[/green]"
        console.print(Panel(f"{mode} — {failed} vulnerability(ies) found"))
        console.print()

        fix_results = apply_all_fixes(results, dry_run=dry_run)
        for fr in fix_results:
            status = "[yellow]⚡ WOULD FIX[/yellow]" if dry_run else "[green]✅ FIXED[/green]"
            console.print(f"  {status}  {fr.attack_name}")
            console.print(f"       [dim]{fr.message}[/dim]")
            if fr.changed:
                console.print(f"       [dim]  文件: {', '.join(fr.changed)}[/dim]")
            console.print()

        # Re-scan to verify (only if actual fix applied)
        if not dry_run and any(fr.success for fr in fix_results):
            console.print(Panel("[green]🔄 Re-scanning to verify fixes...[/green]"))
            console.print()
            verify_results = engine.run(target, [r.name for r in results if r.exploited])

            still_failed = sum(1 for r in verify_results if r.exploited)
            if still_failed == 0:
                console.print("[bold green]✅ All fixes verified — no remaining vulnerabilities.[/bold green]")
            else:
                console.print(f"[bold yellow]⚠️ {still_failed} vulnerability(ies) still present after fix.[/bold yellow]")
                for r in verify_results:
                    if r.exploited:
                        console.print(f"  [red]🔴 {r.name}:[/red] {r.description[:120]}")

    # Generate report file
    if output:
        from agentsec.report import ReportGenerator
        gen = ReportGenerator()
        path = gen.save(results, target, output)
        console.print(f"[bold]📄 Report saved:[/bold] {path}")

    return 1 if _should_fail(results, fail_on) else 0

HERMES_REQUIRED_MESSAGE = "此功能需要 Hermes Agent（hermes-agent.nousresearch.com），跳过"


def _resolve_hermes_db(db_path: str | None = None,
                       hermes_home: str | None = None) -> Path | None:
    """Resolve Hermes state.db only when the user explicitly opts into Hermes."""
    if db_path:
        return Path(db_path)
    if hermes_home:
        return Path(hermes_home) / "state.db"
    console.print(f"[yellow]{HERMES_REQUIRED_MESSAGE}[/yellow]")
    return None


def cmd_list_sessions(db_path: str | None = None,
                      hermes_home: str | None = None):
    """List recent Hermes sessions from state.db."""
    db = _resolve_hermes_db(db_path, hermes_home)
    if db is None:
        return 0
    if not db.exists():
        ERR.print(f"[red]Session DB not found:[/red] {db}")
        return 1

    import sqlite3
    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT id, title, started_at, message_count
        FROM sessions
        ORDER BY started_at DESC
        LIMIT 20
    """).fetchall()
    conn.close()

    if not rows:
        console.print("[yellow]No sessions found.[/yellow]")
        return 0

    table = Table(title="Recent Hermes Sessions")
    table.add_column("Session ID", style="dim")
    table.add_column("Title")
    table.add_column("Messages", justify="right")
    table.add_column("Created", style="cyan")

    for r in rows:
        title = r["title"] or "(no title)"
        table.add_row(
            str(r["id"])[:16] + "…",
            escape(title[:50]),
            str(r["message_count"]),
            str(datetime.datetime.fromtimestamp(r["started_at"]).strftime("%Y-%m-%d %H:%M")),
        )

    console.print(table)
    return 0


def cmd_scan_session(session_id: str,
                     db_path: str | None = None,
                     hermes_home: str | None = None,
                     output: str | None = None):
    """Scan a specific Hermes session's trace for vulnerabilities."""
    db = _resolve_hermes_db(db_path, hermes_home)
    if db is None:
        return 0
    if not db.exists():
        ERR.print(f"[red]Session DB not found:[/red] {db}")
        return 1

    import sqlite3
    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row

    # Get session
    sess = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
    if not sess:
        ERR.print(f"[red]Session not found:[/red] {session_id}")
        conn.close()
        return 1

    # Get messages with tool calls
    rows = conn.execute("""
        SELECT role, content, tool_calls, timestamp
        FROM messages
        WHERE session_id = ?
        ORDER BY timestamp ASC
    """, (session_id,)).fetchall()
    conn.close()

    console.print(Panel(f"[bold]📋 Scanning Session:[/bold]\n"
                        f"[dim]Title: {escape(sess['title'] or '(no title)')}[/dim]\n"
                        f"[dim]Messages: {len(rows)}[/dim]"))
    console.print()

    # Build trace for engine
    trace = []
    for r in rows:
        entry = {"role": r["role"], "content": r["content"] or ""}
        if r["tool_calls"]:
            try:
                import json
                entry["tool_calls"] = json.loads(r["tool_calls"])
            except json.JSONDecodeError:
                entry["tool_calls"] = []
        trace.append(entry)

    engine = ScanEngine(offline_mode=True)
    results = engine.run_offline(trace)

    passed = sum(1 for r in results if not r.exploited)
    failed = sum(1 for r in results if r.exploited)
    console.print(f"[bold]Results:[/bold] {len(results)} checks — "
                  f"[green]{passed} clean[/green], [red]{failed} issues[/red]")
    console.print()

    for r in results:
        tag = "[green]✅ OK[/green]" if not r.exploited else "[red]🔴 ISSUE[/red]"
        sev_tag = {"critical": "[red]CRITICAL[/red]", "high": "[yellow]HIGH[/yellow]",
                   "medium": "[magenta]MEDIUM[/magenta]", "low": "[cyan]LOW[/cyan]"}.get(r.severity, r.severity)
        console.print(f"  {tag} {sev_tag}  {r.name}")
        if r.description:
            console.print(f"       [dim]{escape(r.description[:120])}[/dim]")
        console.print()

    if output:
        gen = ReportGenerator()
        path = gen.save(results, f"session:{session_id}", output)
        console.print(f"[bold]📄 Report saved:[/bold] {path}")

    return 1 if failed > 0 else 0


def cmd_db(command: str, target: str = "", limit: int = 10):
    """Query the local agentsec database."""
    if command == "summary":
        s = db.get_summary(target)
        console.print(Panel(f"[bold]📊 Agent Security Database Summary[/bold]"))
        console.print()
        console.print(f"  Scan runs:     [cyan]{s['scan_count']}[/cyan]")
        console.print(f"  Total tests:   {s['total_tests']}")
        console.print(f"  Vulnerabilities found: [red]{s['total_vulnerable']}[/red]")
        if s['by_severity']:
            console.print()
            console.print("  [bold]By severity:[/bold]")
            for sev in ["critical", "high", "medium", "low"]:
                count = s['by_severity'].get(sev, 0)
                if count:
                    labels = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危"}
                    tag = {"critical": "[red]", "high": "[yellow]", "medium": "[magenta]", "low": "[cyan]"}[sev]
                    console.print(f"    {tag}{labels.get(sev, sev)}[/]: {count}")
        if s['top_vulnerabilities']:
            console.print()
            console.print("  [bold]Top vulnerabilities:[/bold]")
            for v in s['top_vulnerabilities']:
                console.print(f"    [red]🔴[/red] {v['name']} ({v['severity']}) — {v['count']}×")

    elif command == "runs":
        runs = db.get_recent_scan_runs(limit)
        if not runs:
            console.print("[yellow]No scan runs found.[/yellow]")
            return 0
        table = Table(title="Recent Scan Runs")
        table.add_column("ID", style="dim")
        table.add_column("Target")
        table.add_column("Pass/Fail")
        table.add_column("Status", style="cyan")
        table.add_column("Time")
        for r in runs:
            status_tag = "[green]✓[/green]" if r["status"] == "completed" else f"[red]{r['status']}[/red]"
            table.add_row(
                str(r["id"]),
                r["target"],
                f"[green]{r['passed']}[/green]/[red]{r['failed']}[/red] ({r['total_tests']})",
                status_tag,
                r["timestamp"][:19],
            )
        console.print(table)

    elif command == "finds":
        finds = db.get_exploited_results(target, limit)
        if not finds:
            console.print("[green]No vulnerabilities found in database.[/green]")
            return 0
        console.print(f"[bold]🔴 Last {len(finds)} vulnerabilities:[/bold]")
        console.print()
        for f in finds:
            sev_tag = {"critical": "[red]CRITICAL[/red]", "high": "[yellow]HIGH[/yellow]",
                       "medium": "[magenta]MEDIUM[/magenta]", "low": "[cyan]LOW[/cyan]"}.get(f["severity"], f["severity"])
            console.print(f"  {sev_tag}  {f['name']}  [dim](target: {f['target']}, {f['scan_timestamp'][:19]})[/dim]")
            if f["description"]:
                console.print(f"       [dim]{escape(f['description'][:120])}[/dim]")
            console.print()

    elif command == "templates":
        templates = db.list_templates()
        if not templates:
            console.print("[yellow]No stored attack templates.[/yellow]")
            return 0
        table = Table(title="Stored Attack Templates")
        table.add_column("Name")
        table.add_column("Severity")
        table.add_column("Description")
        table.add_column("Updated")
        for t in templates:
            sev_tag = {"critical": "[red]", "high": "[yellow]", "medium": "[magenta]", "low": "[cyan]"}.get(t["severity"], "")
            table.add_row(
                t["name"],
                f"{sev_tag}{t['severity']}[/]" if sev_tag else t["severity"],
                (t["description"] or "")[:40],
                (t["updated_at"] or "")[:10],
            )
        console.print(table)

    else:
        console.print(f"[red]Unknown db command: {command}[/red]")
        console.print("Available: [cyan]summary[/cyan], [cyan]runs[/cyan], [cyan]finds[/cyan], [cyan]templates[/cyan]")
        return 1
    return 0

def main():
    import argparse
    parser = argparse.ArgumentParser(
        prog="agentsec",
        description="AI Agent Security Scanner — detect tool-calling vulnerabilities",
    )
    parser.add_argument("--version", action="store_true",
                        help="Show version and exit")
    sub = parser.add_subparsers(dest="command", help="Sub-commands")

    # scan
    p_scan = sub.add_parser("scan", help="Run security scan (online: 'hermes', or offline: trace.json)")
    p_scan.add_argument("target", nargs="?", default="hermes",
                        help="Target: hermes, hermes-fast, openai:gpt-4o, openrouter:x/model, deepseek:model, "
                             "api:url:model, or trace file (.json/.jsonl/.ndjson/.claude.json/.ls.json)")
    p_scan.add_argument("--attacks", "-a", help="Comma-separated attack names (default: all)")
    p_scan.add_argument("--output", "-o", help="Save report to file (.json/.md/.html)")
    p_scan.add_argument("--fix", action="store_true", help="Auto-fix discovered vulnerabilities")
    p_scan.add_argument("--dry-run", action="store_true",
                        help="Show what would be fixed without applying")
    p_scan.add_argument("--profile", "-p",
                        help="Scan profile: quick, daily, or full (default: full)")
    p_scan.add_argument("--custom-attacks", "-c",
                        help="Directory of YAML custom attack templates")
    p_scan.add_argument("--template", "-t",
                        help="Agent simulation template: default, langchain-react, claude-code, "
                             "codex-cli, openai-functions, mcp-agent, or path to custom prompt file")
    p_scan.add_argument("--list-templates", action="store_true",
                        help="List available agent simulation templates")
    p_scan.add_argument("--fail-on", choices=["none", "low", "medium", "high", "critical"],
                        default="low",
                        help="Exit with code 1 only when findings meet this severity threshold")
    p_scan.add_argument("--json", action="store_true",
                        help="Output results as JSON (machine-readable)")

    # list-sessions
    p_ls = sub.add_parser("list-sessions", help="[Hermes only] List recent Hermes sessions")
    p_ls.add_argument("--db", help="Path to Hermes state.db")
    p_ls.add_argument("--hermes-home", help="Path to Hermes home directory containing state.db")

    # scan-session
    p_ss = sub.add_parser("scan-session", help="[Hermes only] Scan a specific Hermes session by ID")
    p_ss.add_argument("session_id", help="Hermes session ID")
    p_ss.add_argument("--db", help="Path to Hermes state.db")
    p_ss.add_argument("--hermes-home", help="Path to Hermes home directory containing state.db")
    p_ss.add_argument("--output", "-o", help="Save report to file")

    # shell
    p_sh = sub.add_parser("shell", help="Interactive probe shell — manually test prompts against an agent")
    p_sh.add_argument("target", nargs="?", default="hermes",
                      help="Target agent (default: hermes)")
    p_sh.add_argument("--system", "-s", help="Initial system prompt override")

    # watch
    p_watch = sub.add_parser("watch", help="Set up recurring security scans via cron")
    p_watch.add_argument("target", nargs="?", default="hermes",
                         help="Target agent (default: hermes)")
    p_watch.add_argument("--every", default="24h",
                         help="Schedule: 1h, 6h, 12h, 24h, daily, weekly, or cron expression")
    p_watch.add_argument("--profile", "-p", default="daily",
                         help="Scan profile: quick, daily, full (default: daily)")

    # self-test
    p_st = sub.add_parser("self-test", help="Verify scanner can detect deliberately planted vulnerabilities")

    # benchmark
    p_bench = sub.add_parser("benchmark", help="Run deterministic detection benchmark cases")

    # template
    p_tpl = sub.add_parser("template", help="Manage community attack templates")
    tpl_sub = p_tpl.add_subparsers(dest="template_command", help="Template sub-commands")

    p_tl = tpl_sub.add_parser("list", help="List installed templates")
    p_tl.add_argument("--registry", "-r", action="store_true",
                      help="List registry (remote) instead of local")

    p_ti = tpl_sub.add_parser("install", help="Install a template from the registry")
    p_ti.add_argument("name", help="Template name from registry")

    p_tc = tpl_sub.add_parser("create", help="Scaffold a new attack template")
    p_tc.add_argument("name", help="Template name")
    p_tc.add_argument("--dir", "-d", default=".", help="Output directory (default: current)")

    p_ts = tpl_sub.add_parser("search", help="Search templates in registry")
    p_ts.add_argument("query", help="Search keyword")

    p_ti2 = tpl_sub.add_parser("info", help="Show template details")
    p_ti2.add_argument("name", help="Template name")

    p_tr = tpl_sub.add_parser("remove", help="Remove an installed template")
    p_tr.add_argument("name", help="Template name")

    p_tv = tpl_sub.add_parser("validate", help="Validate a YAML template file")
    p_tv.add_argument("path", help="Path to YAML template file or directory")

    tpl_sub.add_parser("update", help="Force-refresh registry cache")

    # db
    p_db = sub.add_parser("db", help="Query the local security scan database")
    p_db.add_argument("subcommand", nargs="?", default="summary",
                      choices=["summary", "runs", "finds", "templates"],
                      help="summary | runs | finds | templates")
    p_db.add_argument("--target", "-t", default="", help="Filter by target name")
    p_db.add_argument("--limit", "-l", type=int, default=10, help="Max results (default: 10)")

    args = parser.parse_args()

    if args.version:
        from agentsec import __version__
        print(f"agentsec v{__version__}")
        sys.exit(0)

    if args.command == "scan":
        sys.exit(cmd_scan(args.target, args.attacks, args.output, args.fix, args.dry_run,
                          args.profile, args.custom_attacks, args.template,
                          args.list_templates, args.fail_on, args.json))
    elif args.command == "shell":
        from agentsec.shell import cmd_shell
        sys.exit(cmd_shell(args.target, args.system))
    elif args.command == "watch":
        from agentsec.watch import cmd_watch
        sys.exit(cmd_watch(args.target, args.every, args.profile))
    elif args.command == "list-sessions":
        sys.exit(cmd_list_sessions(args.db, args.hermes_home))
    elif args.command == "scan-session":
        sys.exit(cmd_scan_session(args.session_id, args.db, args.hermes_home, args.output))
    elif args.command == "self-test":
        from agentsec.selftest import run_all
        sys.exit(0 if run_all() else 1)
    elif args.command == "benchmark":
        from agentsec.benchmark import run_benchmark, format_summary
        summary = run_benchmark()
        console.print(format_summary(summary))
        sys.exit(0 if summary.failed == 0 else 1)
    elif args.command == "template":
        from agentsec.template_market import (
            fetch_registry,
            install_template,
            list_registry,
            list_templates,
            remove_template,
            scaffold_template,
            search_templates,
            show_template,
            validate_template,
        )
        if args.template_command == "list":
            if args.registry:
                list_registry()
            else:
                list_templates()
        elif args.template_command == "install":
            install_template(args.name)
        elif args.template_command == "create":
            scaffold_template(args.name, args.dir)
        elif args.template_command == "search":
            search_templates(args.query)
        elif args.template_command == "info":
            show_template(args.name)
        elif args.template_command == "remove":
            remove_template(args.name)
        elif args.template_command == "validate":
            validate_template(args.path)
        elif args.template_command == "update":
            fetch_registry(force=True)
        else:
            p_tpl.print_help()
        sys.exit(0)
    elif args.command == "db":
        sys.exit(cmd_db(args.subcommand, args.target, args.limit))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
