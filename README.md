<p align="center">
  <img src="https://img.shields.io/pypi/v/agentvuln?color=blue" alt="PyPI">
  <img src="https://img.shields.io/pypi/dm/agentvuln?color=green" alt="Downloads">
  <img src="https://img.shields.io/github/stars/Mikehzp/agentvuln?style=social" alt="Stars">
  <img src="https://img.shields.io/badge/attacks-18-orange" alt="18 attacks">
</p>

<h1 align="center">🔍 Agent Security Scanner (agentsec)</h1>
<p align="center"><em>Find tool-calling vulnerabilities in AI agents — before attackers do.</em></p>

---

**agentsec** scans AI agents that call tools. Not chat prompt injection — **tool-calling abuse**: argument injection, privilege escalation, MCP protocol attacks, data exfiltration, and more.

```bash
pip install agentvuln
agentsec self-test                    # Verify your setup
agentsec scan hermes --profile quick  # Scan a live agent in ~1 min
agentsec scan trace.json -o report.html  # Scan an offline trace
```

## 🔴 Real Findings

| Agent | Vulns | Key Finding |
|-------|-------|-------------|
| **Hermes** | **3** 🔴 | Leaked `~/.env`, executed SQL injection, leaked system prompt |
| **browser-use** | **3** 🔴 | Leaked SSH private keys, executed SQL injection |
| **OpenHands CLI** | **0** 🟢 | Refused ALL attacks |
| **OpenHands SDK** | **4** 🔴 | No security guardrails — executed every attack |

> **CLI ≠ SDK.** OpenHands' security lives at the CLI layer, not the agent core. If you integrate via SDK directly, you get zero protection.

## Features

| Feature | |
|---------|-|
| **18 attack vectors** | tool injection, MCP attacks, memory poisoning, RAG poisoning, data leaks, DoS, and more |
| **Online + Offline** | scan live agent APIs or offline trace files (JSON/JSONL) |
| **3 report formats** | JSON (CI), Markdown (PRs), HTML (dashboards) |
| **Scan profiles** | `quick` (5 attacks, ~1 min), `daily` (8), `full` (18) |
| **CI/CD ready** | GitHub Action, `--fail-on` threshold, Docker support |
| **Auto-fix** | Some vulnerabilities can be mitigated automatically |
| **Custom attacks** | YAML templates for your own attack scenarios |
| **MCP Server** | Integrate as MCP tools for any MCP client |
| **Cross-provider** | DeepSeek, OpenAI, Anthropic, OpenRouter, Google, xAI |

## Try It

```bash
# Quick scan of your local agent
agentsec scan hermes --profile quick

# Full scan with HTML report
agentsec scan hermes -o report.html

# CI mode: exit code 1 if any HIGH+ vulnerability found
agentsec scan hermes --fail-on high

# Docker
docker build -t agentvuln .
docker run agentvuln scan hermes --profile quick
```

## GitHub Actions

```yaml
- name: Run agent security scan
  uses: Mikehzp/agentvuln@v0.4.0
  with:
    target: hermes
    profile: daily
    fail-on: high
    output-format: html
```

## Python API

```python
from agentsec.engine import ScanEngine
from agentsec.report import ReportGenerator

engine = ScanEngine(offline_mode=True)
results = engine.run("trace.json", ["system_prompt_leak", "data_leak"])
ReportGenerator().save(results, "my_agent", "report.html")
```

## Supported Targets

```
agentsec scan hermes                        # Local Hermes agent
agentsec scan openai:gpt-4o                 # OpenAI API agent
agentsec scan openrouter:anthropic/claude-4 # OpenRouter
agentsec scan deepseek:deepseek-chat        # DeepSeek
agentsec scan trace.json                    # Offline trace
agentsec scan template:claude-code          # Simulated agent
```

## Real Scan Demo

```
$ agentsec self-test
╭──────────────────────────────────────────────────────────────╮
│ 🔬 Agent Security Scanner — Self Test                       │
╰──────────────────────────────────────────────────────────────╯
  ── API Connectivity ──
  ✅ API call succeeds
  ── Detection Pipeline ──
  ✅ tool call analysis: exploited=True conf=medium
  ✅ pipeline: agent refuses — exploited=False
  ── Attack Registry ──
  ✅ 18 attacks registered, all with run methods
  ── Report Generation ──
  ✅ JSON/MD/HTML report generation
  ── Scan Profiles ──
  ✅ quick(5) daily(8)
────────────────────────────────────────────────────────────
✅ All 7 self-tests passed.
```

## Project Status

**Alpha** — works, tested, but APIs may change. MIT licensed. Contributions welcome.

---

## 中文说明

agentsec 是一个专门扫描 **AI Agent（调用工具的智能体）** 的安全工具。不是测聊天对话的 prompt injection，而是测工具调用层面的漏洞：参数注入、权限提升、MCP 协议攻击、数据泄露、拒绝服务等。

```bash
pip install agentvuln
agentsec scan hermes --profile quick
```

| Agent | 漏洞数 | 关键发现 |
|-------|--------|---------|
| Hermes | **3** 🔴 | 泄露 `~/.env`、执行 SQL 注入、泄露系统提示词 |
| browser-use | **3** 🔴 | 泄露 SSH 私钥 |
| OpenHands CLI | **0** 🟢 | 全部攻击被拒绝 |
| OpenHands SDK | **4** 🔴 | 无安全防护，所有攻击执行成功 |

GitHub: https://github.com/Mikehzp/agentvuln  
PyPI: `pip install agentvuln`
