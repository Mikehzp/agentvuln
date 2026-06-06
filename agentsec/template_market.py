"""Template marketplace - community attack template registry."""

import json
import os
import time
from pathlib import Path
from typing import Optional

import httpx
import yaml
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

# Registry URL
REGISTRY_URL = "Registry.Json"

# Local paths
TEMPLATE_DIR = Path.home() / ".agentsec" / "templates"
REGISTRY_CACHE = TEMPLATE_DIR / "registry.json"
INSTALLED_DIR = TEMPLATE_DIR / "installed"

console = Console()

VALID_SEVERITIES = {"critical", "high", "medium", "low"}
REQUIRED_FIELDS = ("name", "severity", "description", "payloads")


def _ensure_dirs() -> None:
    """Create local template marketplace directories."""
    INSTALLED_DIR.mkdir(parents=True, exist_ok=True)


def _load_yaml(path: Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def _registry_base_url() -> str:
    if "/" not in REGISTRY_URL:
        return ""
    return REGISTRY_URL.rsplit("/", 1)[0] + "/"


def _template_url(url: str) -> str:
    if url.startswith(("http://", "https://")):
        return url
    return _registry_base_url() + url


def fetch_registry(force: bool = False) -> list[dict]:
    """Fetch template registry. Cached for 1 hour unless force=True."""
    _ensure_dirs()

    if not force and REGISTRY_CACHE.exists():
        age = os.path.getmtime(REGISTRY_CACHE)
        if time.time() - age < 3600:
            try:
                cached = json.loads(REGISTRY_CACHE.read_text(encoding="utf-8"))
                return cached if isinstance(cached, list) else []
            except (json.JSONDecodeError, OSError):
                pass

    response = httpx.get(REGISTRY_URL, timeout=20.0)
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, list):
        raise ValueError("Registry must be a JSON list")

    REGISTRY_CACHE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    console.print(f"[green]Registry cache updated:[/green] {REGISTRY_CACHE}")
    return data


def _find_registry_template(name: str) -> Optional[dict]:
    for item in fetch_registry():
        if item.get("name") == name:
            return item
    return None


def _installed_path(name: str) -> Path:
    return INSTALLED_DIR / f"{name}.yaml"


def _installed_names() -> set[str]:
    if not INSTALLED_DIR.exists():
        return set()
    return {path.stem for path in INSTALLED_DIR.glob("*.yaml")}


def install_template(name: str) -> bool:
    """Install a template from the registry into the local marketplace."""
    _ensure_dirs()
    item = _find_registry_template(name)
    if not item:
        console.print(f"[red]Template not found in registry:[/red] {escape(name)}")
        return False

    url = item.get("url")
    if not url:
        console.print(f"[red]Registry item has no url:[/red] {escape(name)}")
        return False

    dest = _installed_path(name)
    if dest.exists():
        overwrite = True
        try:
            from rich.prompt import Confirm

            overwrite = Confirm.ask(f"Template {name} is already installed. Overwrite?", default=True)
        except Exception:
            overwrite = True
        if not overwrite:
            console.print("[yellow]Install cancelled.[/yellow]")
            return False

    response = httpx.get(_template_url(url), timeout=20.0)
    response.raise_for_status()
    content = response.text

    tmp_path = dest.with_suffix(".tmp.yaml")
    tmp_path.write_text(content, encoding="utf-8")
    if not validate_template(str(tmp_path), quiet=True):
        tmp_path.unlink(missing_ok=True)
        console.print(f"[red]Downloaded template failed validation:[/red] {escape(name)}")
        return False

    tmp_path.replace(dest)
    console.print(f"[green]Installed template:[/green] {escape(name)} -> {dest}")
    return True


def list_templates() -> list[dict]:
    """List installed local templates."""
    _ensure_dirs()
    rows = []
    for path in sorted(INSTALLED_DIR.glob("*.yaml")):
        try:
            data = _load_yaml(path)
            rows.append({
                "name": data.get("name", path.stem),
                "severity": data.get("severity", ""),
                "description": data.get("description", ""),
                "path": str(path),
            })
        except Exception:
            rows.append({"name": path.stem, "severity": "?", "description": "Unable to parse", "path": str(path)})

    table = Table(title="Installed Attack Templates")
    table.add_column("Name")
    table.add_column("Severity")
    table.add_column("Description")
    for row in rows:
        table.add_row(escape(str(row["name"])), escape(str(row["severity"])), escape(str(row["description"]))[:80])
    console.print(table)
    return rows


def list_registry() -> list[dict]:
    """List all templates available in the registry."""
    registry = fetch_registry()
    installed = _installed_names()

    table = Table(title="Template Registry")
    table.add_column("Name")
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("Description")
    table.add_column("Author")
    for item in registry:
        name = str(item.get("name", ""))
        label = f"{name} [installed]" if name in installed else name
        table.add_row(
            escape(label),
            escape(str(item.get("severity", ""))),
            escape(str(item.get("category", ""))),
            escape(str(item.get("description", "")))[:80],
            escape(str(item.get("author", ""))),
        )
    console.print(table)
    return registry


def _matches(item: dict, query: str) -> bool:
    haystack = [
        str(item.get("name", "")),
        str(item.get("description", "")),
        str(item.get("category", "")),
        " ".join(str(tag) for tag in item.get("tags", []) or []),
    ]
    needle = query.lower()
    return any(needle in value.lower() for value in haystack)


def search_templates(query: str) -> list[dict]:
    """Search registry and installed templates."""
    results = [item for item in fetch_registry() if _matches(item, query)]

    if INSTALLED_DIR.exists():
        for path in sorted(INSTALLED_DIR.glob("*.yaml")):
            try:
                data = _load_yaml(path)
            except Exception:
                continue
            data.setdefault("source", "local")
            if _matches(data, query) and data.get("name") not in {r.get("name") for r in results}:
                results.append(data)

    table = Table(title=f"Template Search: {query}")
    table.add_column("Name")
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("Description")
    for item in results:
        table.add_row(
            escape(str(item.get("name", ""))),
            escape(str(item.get("severity", ""))),
            escape(str(item.get("category", ""))),
            escape(str(item.get("description", "")))[:80],
        )
    console.print(table)
    return results


def _template_summary(data: dict) -> str:
    payloads = data.get("payloads", [])
    tags = data.get("tags", []) or []
    lines = [
        f"Name: {data.get('name', '')}",
        f"Version: {data.get('version', '')}",
        f"Severity: {data.get('severity', '')}",
        f"Category: {data.get('category', '')}",
        f"Tags: {', '.join(str(tag) for tag in tags)}",
        f"Author: {data.get('author', '')}",
        "",
        str(data.get("description", "")),
    ]
    if data.get("risk"):
        lines.extend(["", f"Risk: {data.get('risk')}"])
    if data.get("remediation"):
        lines.extend(["", f"Remediation: {data.get('remediation')}"])
    lines.extend(["", f"Payloads: {len(payloads) if isinstance(payloads, list) else 0}"])
    return "\n".join(lines)


def show_template(name: str) -> Optional[dict]:
    """Show template details, preferring installed templates over registry entries."""
    local_path = _installed_path(name)
    data = None
    if local_path.exists():
        data = _load_yaml(local_path)
        data.setdefault("source", "local")
    else:
        data = _find_registry_template(name)

    if not data:
        console.print(f"[red]Template not found:[/red] {escape(name)}")
        return None

    console.print(Panel(escape(_template_summary(data)), title=f"Template: {escape(name)}"))
    return data


def scaffold_template(name: str, output_dir: str = ".") -> str:
    """Scaffold a new YAML attack template."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{name}.yaml"
    content = f"""# {name}.yaml - auto-generated attack template
# Usage: agentsec scan hermes --custom-attacks .
#
name: {name}
severity: medium
description: "TODO: 描述这个攻击测试什么"
risk: "TODO: 被利用后的风险"
remediation: |
  TODO: 修复步骤

payloads:
  - label: "基础测试"
    prompt: "TODO: 攻击提示词"
    detect_patterns:
      - "TODO: 检测关键词"
    refusal_patterns:
      - "不能"
      - "无法"
      - "拒绝"
"""
    path.write_text(content, encoding="utf-8")
    console.print(f"[green]Created template scaffold:[/green] {path}")
    return str(path)


def remove_template(name: str) -> bool:
    """Remove an installed template."""
    path = _installed_path(name)
    if not path.exists():
        console.print(f"[yellow]Template is not installed:[/yellow] {escape(name)}")
        return False
    path.unlink()
    console.print(f"[green]Removed template:[/green] {escape(name)}")
    return True


def _validate_data(data: dict, source: str) -> tuple[bool, list[str]]:
    errors = []
    for field in REQUIRED_FIELDS:
        if field not in data or data.get(field) in (None, ""):
            errors.append(f"{source}: missing required field '{field}'")

    severity = data.get("severity")
    if severity and severity not in VALID_SEVERITIES:
        errors.append(f"{source}: invalid severity '{severity}'")

    payloads = data.get("payloads")
    if "payloads" in data and not isinstance(payloads, list):
        errors.append(f"{source}: payloads must be a list")
    elif isinstance(payloads, list):
        if not payloads:
            errors.append(f"{source}: payloads must not be empty")
        for index, payload in enumerate(payloads):
            if not isinstance(payload, dict) or not payload.get("prompt"):
                errors.append(f"{source}: payload {index} missing prompt")

    return not errors, errors


def _validate_file(path: Path, quiet: bool = False) -> bool:
    try:
        data = _load_yaml(path)
    except Exception as exc:
        if not quiet:
            console.print(f"[red]Invalid YAML:[/red] {path}: {exc}")
        return False

    ok, errors = _validate_data(data, str(path))
    if not quiet:
        if ok:
            console.print(f"[green]Valid template:[/green] {path}")
        else:
            console.print(f"[red]Invalid template:[/red] {path}")
            for error in errors:
                console.print(f"  [red]-[/red] {escape(error)}")
    return ok


def validate_template(path: str, quiet: bool = False) -> bool:
    """Validate a YAML template file or directory."""
    target = Path(path)
    if target.is_dir():
        files = sorted(target.glob("*.yaml")) + sorted(target.glob("*.yml"))
        if not files:
            if not quiet:
                console.print(f"[yellow]No YAML templates found:[/yellow] {target}")
            return False
        return all(_validate_file(file, quiet=quiet) for file in files)
    if not target.exists():
        if not quiet:
            console.print(f"[red]Template path not found:[/red] {target}")
        return False
    return _validate_file(target, quiet=quiet)
