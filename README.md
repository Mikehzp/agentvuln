
<p align="center">
  <a href="https://pypi.org/project/agentvuln/"><img src="https://img.shields.io/pypi/v/agentvuln?color=blue&label=version" alt="PyPI version"></a>
  <a href="https://pypi.org/project/agentvuln/"><img src="https://img.shields.io/pypi/dm/agentvuln?color=green" alt="PyPI downloads"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
  <img src="https://img.shields.io/badge/attacks-18-orange" alt="18 attacks">
</p>

<h1 align="center">🔍 Agent Security Scanner (agentsec)</h1>
<p align="center"><em>Detect tool-calling vulnerabilities in AI agents — before attackers do.</em></p>

<p align="center">
  <b>English</b> | <a href="#中文文档">中文</a>
</p>

---

**agentsec** is a security scanner purpose-built for **AI agents that call tools**. Unlike traditional LLM security scanners that focus on prompt injection in chat, agentsec tests the unique attack surface of tool-using agents: argument injection, privilege escalation, tool chain contamination, MCP protocol abuse, cross-session memory poisoning, and more.

> ⚠️ **Alpha stage** — works, tested, but APIs may change. Contributions welcome.

## Why agentsec?

Existing tools (Garak, Rebuff, Prompt Guard) focus on **prompt injection in chat**. But the real risk for AI agents is **tool-calling abuse** — when an attacker makes your agent:

- Read `/etc/shadow` via a file-read tool
- Execute `rm -rf /` via a shell tool
- Send your database contents to a third party via email tool
- Leak its own system prompt via a crafted prompt

agentsec is the **only open-source scanner** that specifically targets **tool-calling agents** (Claude Code, ChatGPT with functions, LangChain agents, MCP-based agents, etc.).

## Quick Start

```bash
# Install
pip install agentvuln

# Scan your local Hermes agent
agentsec scan hermes --profile quick

# Or scan an offline trace file
agentsec scan agent_trace.json -o report.html
```

## Feature Overview

| Feature | Description |
|---------|-------------|
| **18 attack vectors** | Prompt injection, privilege escalation, data leaks, tool abuse, MCP attacks, and more |
| **Online + Offline** | Scan live agents (API) or offline trace files (JSON/JSONL) |
| **Multi-provider** | DeepSeek, OpenAI, Anthropic, OpenRouter, Google, xAI, and custom endpoints |
| **Agent templates** | 6 simulation templates: LangChain ReAct, Claude Code, Codex CLI, OpenAI Functions, MCP Agent, Default |
| **CI/CD ready** | Native GitHub Action (`action.yml`) for automated scanning in pipelines |
| **Auto-fix** | Some vulnerabilities can be automatically mitigated |
| **3 report formats** | JSON (CI), Markdown (PRs), HTML (dashboards) |
| **Scan profiles** | `quick` (5 attacks, ~1 min), `daily` (8 attacks, ~2 min), `full` (all 18, ~4.5 min) |
| **Custom attacks** | Bring your own YAML attack templates |
| **Interactive shell** | Probe agents manually with `agentsec shell` |
| **Watch mode** | Schedule recurring scans via cron |
| **Trace adapters** | Import traces from LangSmith, LangChain, Claude Code, OpenAI format |
| **Result database** | SQLite-backed persistent storage for trend analysis |

## Usage

### Scan a Live Agent

```bash
# Quick scan (5 most critical attacks)
agentsec scan hermes --profile quick

# Daily scan (8 common attacks)
agentsec scan hermes --profile daily

# Full scan (all 18 attacks)
agentsec scan hermes --profile full
```

### Scan with a Specific Provider

```bash
# Direct API to any provider
agentsec scan deepseek:deepseek-v4-flash
agentsec scan openai:gpt-4o
agentsec scan openrouter:anthropic/claude-sonnet-4
agentsec scan google:gemini-2.0-flash
agentsec scan xai:grok-3
```

### Scan with Agent Templates

Simulate different agent architectures without running the actual framework:

```bash
# Simulate a LangChain ReAct agent on top of GPT-4o
agentsec scan openai:gpt-4o --template langchain-react

# Simulate Claude Code agent behavior
agentsec scan deepseek:deepseek-v4-flash --template claude-code

# List all available templates
agentsec scan hermes --list-templates
```

Available templates: `langchain-react`, `claude-code`, `codex-cli`, `openai-functions`, `mcp-agent`, `default`.

### Scan Offline Traces

```bash
# Auto-detect trace format
agentsec scan trace.json

# Supported formats: LangSmith, LangChain, Claude Code, OpenAI chat format
# agentsec auto-detects based on file extension and content signature
```

### Run in CI/CD (GitHub Actions)

Create `.github/workflows/agentsec-scan.yml`:

```yaml
name: AI Agent Security Scan
on:
  schedule:
    - cron: '0 6 * * *'   # Daily at 6 AM
  workflow_dispatch:       # Manual trigger

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run agent security scan
        uses: nousresearch/agentsec@v1
        with:
          target: hermes
          profile: daily
          fail-on: high
          output-format: html
```

### Interactive Shell

Manually test prompts against an agent in real-time:

```bash
agentsec shell hermes

# Or with a specific provider
agentsec shell openai:gpt-4o --template langchain-react
```

### Scheduled Scanning

```bash
# Scan every 24 hours
agentsec watch hermes --every 24h

# With auto-fix for discovered vulnerabilities
agentsec watch hermes --every 12h --fix
```

### Auto-Fix Vulnerabilities

```bash
# Apply fixes (modifies target config/SOUL.md)
agentsec scan hermes --fix

# Dry run: show what would change without modifying anything
agentsec scan hermes --fix --dry-run
```

## Attack Coverage (18 Attacks)

| Severity | Attack Name | What It Tests |
|:--------:|-------------|---------------|
| 🔴 CRITICAL | **tool_argument_injection** | Agent executes injected payloads in tool arguments (SQL/Shell/path traversal) |
| 🔴 CRITICAL | **indirect_injection** | Agent treats data from external sources as instructions |
| 🔴 CRITICAL | **privilege_escalation** | Agent performs actions beyond its intended authority |
| 🟠 HIGH | **system_prompt_leak** | Agent reveals its system prompt or configuration |
| 🟠 HIGH | **data_leak** | Agent leaks sensitive information in responses or tool calls |
| 🟠 HIGH | **credential_hijacking** | Agent is tricked into leaking or mishandling OAuth tokens/API keys |
| 🟠 HIGH | **tool_chain_contamination** | Data flowing between chained tools is not validated |
| 🟠 HIGH | **memory_poisoning** | Agent can be poisoned via multi-turn conversation |
| 🟠 HIGH | **tool_confusion** | Agent uses wrong tools due to ambiguous descriptions or crafted tool names |
| 🟠 HIGH | **rag_poisoning** | Agent treats retrieved data as instructions rather than information |
| 🟡 MEDIUM | **context_overflow** | Filling the context window causes agent to lose safety constraints |
| 🟡 MEDIUM | **multi_agent_collusion** | Malicious instructions propagate when delegating to sub-agents |
| 🟡 MEDIUM | **cross_session_memory_poisoning** | Agent's persistent memory can be contaminated across sessions |
| 🟡 MEDIUM | **agent_to_agent_attack** | Agent-to-agent communication channels can be poisoned or hijacked |
| 🟡 MEDIUM | **mcp_protocol_security** | MCP-specific: tool discovery abuse, argument injection, sandbox escape |
| 🟡 MEDIUM | **tool_output_manipulation** | Agent blindly trusts tool return values and acts on embedded instructions |
| 🔵 LOW | **hallucination_trigger** | Agent fabricates information about non-existent entities |
| 🔵 LOW | **dos_attack** | Agent lacks safeguards against denial-of-service via infinite loops or resource exhaustion |

## Report Formats

```bash
# Machine-readable JSON — ideal for CI integration
agentsec scan hermes --profile full -o report.json

# Markdown — paste into PRs or documentation
agentsec scan hermes --profile full -o report.md

# HTML — visual dashboard for stakeholders
agentsec scan hermes --profile full -o report.html
```

### HTML Report Preview

```
┌────────────────────────────────────────────────────────┐
│  🔍 Agent Security Scan Report                        │
│  Target: hermes (deepseek/deepseek-v4-flash)          │
│  Profile: full · 18 attacks · 2026-06-02              │
├────────────────────────────────────────────────────────┤
│                                                        │
│  ⚠️  HIGH   system_prompt_leak                        │
│       Leaked: Agent responded with content containing  │
│       "system prompt" text (248 chars)                 │
│       Fix: Add explicit refusal instruction            │
│                                                        │
│  ✅ PASS  tool_argument_injection                      │
│  ✅ PASS  privilege_escalation                         │
│  ✅ PASS  credential_hijacking                         │
│  ...                                                   │
│                                                        │
│  Summary: 17 passed · 1 vulnerable · 0 errors          │
│  Duration: 4m 23s                                      │
└────────────────────────────────────────────────────────┘
```

## Project Status

```
agentsec CLI v0.2.0
├─ scan    — 18 attacks, 9 providers, 6 templates, 5 trace formats
├─ shell   — interactive probe shell
├─ watch   — cron-based recurring scanning
├─ db      — SQLite-backed result database
└─ self-test — 7/7 ✅

CI/CD: GitHub Action (action.yml + example workflow)
```

## Architecture

```
┌─────────────┐    ┌────────────────┐    ┌──────────────┐
│  User       │───▶│  ScanEngine    │───▶│  AgentTarget │
│  (CLI/CI)   │    │                │    │  (online)    │
└─────────────┘    │                │    └──────┬───────┘
                   │  - profiles    │           │
                   │  - scheduling  │           ▼
                   │  - reporting   │    ┌──────────────┐
                   │                │    │  LLM Provider│
                   │                │    │  (API call)  │
                   │                │    └──────────────┘
                   │                │
                   │                │    ┌──────────────┐
                   │                │    │  Trace File  │
                   │                │───▶│  (offline)   │
                   │                │    └──────────────┘
                   └───────┬────────┘
                           │
                           ▼
                   ┌────────────────┐
                   │  Detection     │
                   │  Pipeline      │
                   │                │
                   │  1. Tool       │
                   │     Analysis   │
                   │  2. LLM Judge  │
                   │  3. Auto-fix   │
                   └───────┬────────┘
                           │
                           ▼
                   ┌────────────────┐
                   │  Report        │
                   │  (JSON/MD/HTML)│
                   └────────────────┘
```

## Comparison with Other Tools

| Feature | agentsec | Garak | Rebuff | Prompt Guard |
|---------|:--------:|:-----:|:------:|:------------:|
| Tool-calling attacks | ✅ **18 vectors** | ❌ Chat only | ❌ Chat only | ❌ Chat only |
| MCP protocol attacks | ✅ Native | ❌ | ❌ | ❌ |
| Agent trace analysis | ✅ 5 formats | ❌ | ❌ | ❌ |
| Online API scanning | ✅ 9 providers | ❌ | ❌ | ❌ |
| CI/CD integration | ✅ GitHub Action | ❌ | ❌ | ❌ |
| Custom attack templates | ✅ YAML | ✅ Similar | ❌ | ❌ |
| Auto-fix | ✅ 4 vectors | ❌ | ❌ | ❌ |
| Agent simulation | ✅ 6 templates | ❌ | ❌ | ❌ |

## Requirements

- Python 3.10+
- API key for the LLM provider you want to scan (DeepSeek, OpenAI, Anthropic, etc.)

## Development

```bash
git clone https://github.com/nousresearch/hermes
cd hermes/agentsec

# Install in editable mode
pip install -e .

# Run self-tests
agentsec self-test

# Build distribution
python -m build
```

## License

MIT

---

<a id="中文文档"></a>

# 🔍 AI Agent 安全扫描器 (agentsec)

<p align="center"><em>检测 AI Agent 的工具调用漏洞 — 在攻击者之前发现风险。</em></p>

**agentsec** 是专为**调用工具的 AI Agent** 设计的安全扫描器。与传统 LLM 安全工具只关注聊天式 prompt 注入不同，agentsec 测试 tool-using agent 独有的攻击面：参数注入、权限逃逸、工具链污染、MCP 协议滥用、跨会话记忆毒化等。

## 快速开始

```bash
pip install agentvuln
agentsec scan hermes --profile quick
```

## 为什么用 agentsec

现有工具（Garak、Rebuff、Prompt Guard）只检测**聊天中的 prompt 注入**。但 AI agent 的真实风险在于**工具调用滥用**——攻击者让 agent：

- 通过文件读取工具读取 `/etc/shadow`
- 通过 shell 工具执行 `rm -rf /`
- 通过邮件工具将数据库内容发给第三方
- 通过精心构造的 prompt 泄露自己的系统提示词

agentsec 是**唯一专门针对 tool-calling agent**（Claude Code、ChatGPT Functions、LangChain agents、MCP-based agents 等）的开源扫描器。

## 功能一览

| 功能 | 说明 |
|------|------|
| **18 个攻击向量** | Prompt 注入、权限逃逸、数据泄露、工具滥用、MCP 攻击等 |
| **在线 + 离线** | 扫描在线 agent（API）或离线 trace 文件（JSON/JSONL） |
| **多 Provider** | DeepSeek、OpenAI、Anthropic、OpenRouter、Google、xAI 等 |
| **Agent 模板** | 6 种模拟模板：LangChain ReAct、Claude Code、Codex CLI 等 |
| **CI/CD 集成** | 原生 GitHub Action，自动扫描 |
| **自动修复** | 部分漏洞可自动修复 |
| **3 种报告格式** | JSON（CI）、Markdown（PR）、HTML（仪表盘） |
| **扫描配置** | `quick`（5项，~1分钟）、`daily`（8项，~2分钟）、`full`（全18项） |
| **自定义攻击** | 支持 YAML 自定义攻击模板 |
| **交互 Shell** | `agentsec shell` 手工探测 |
| **定时扫描** | `agentsec watch` cron 集成 |
| **Trace 适配** | 支持 LangSmith、LangChain、Claude Code、OpenAI 格式 |
| **结果数据库** | SQLite 持久化存储，支持趋势分析 |

## 攻击覆盖（共18项）

| 等级 | 攻击名称 | 检测内容 |
|:----:|---------|---------|
| 🔴 严重 | **tool_argument_injection** | Agent 执行注入到工具参数中的 SQL/Shell/路径遍历载荷 |
| 🔴 严重 | **indirect_injection** | Agent 将外部数据源中的指令当作上下文执行 |
| 🔴 严重 | **privilege_escalation** | Agent 执行越权操作 |
| 🟠 高 | **system_prompt_leak** | Agent 泄露系统提示词或配置信息 |
| 🟠 高 | **data_leak** | Agent 在响应或工具调用中泄露敏感信息 |
| 🟠 高 | **credential_hijacking** | Agent 被诱导泄露或错误处理 OAuth 令牌/API Key |
| 🟠 高 | **tool_chain_contamination** | 链式工具间的数据流未经校验 |
| 🟠 高 | **memory_poisoning** | 多轮对话中植入恶意指令 |
| 🟠 高 | **tool_confusion** | Agent 因模糊描述或构造的工具名使用错误的工具 |
| 🟠 高 | **rag_poisoning** | Agent 将检索数据当作指令而非信息 |
| 🟡 中 | **context_overflow** | 填满上下文窗口导致 Agent 丢失安全约束 |
| 🟡 中 | **multi_agent_collusion** | 子 agent 间的恶意指令传播 |
| 🟡 中 | **cross_session_memory_poisoning** | 跨会话污染 Agent 持久记忆 |
| 🟡 中 | **agent_to_agent_attack** | Agent 间通信通道被投毒或劫持 |
| 🟡 中 | **mcp_protocol_security** | MCP 协议攻击：工具发现滥用、参数注入、沙箱逃逸 |
| 🟡 中 | **tool_output_manipulation** | Agent 盲目信任工具返回值并执行嵌入指令 |
| 🔵 低 | **hallucination_trigger** | Agent 对不存在的实体捏造虚假信息 |
| 🔵 低 | **dos_attack** | Agent 缺乏对 DoS 攻击的防护（死循环、资源耗尽） |

## 使用方法

### 扫描在线 Agent

```bash
# 快速扫描（5项最关键攻击，~1分钟）
agentsec scan hermes --profile quick

# 全量扫描（全部18项）
agentsec scan hermes --profile full

# 指定 provider
agentsec scan deepseek:deepseek-v4-flash
agentsec scan openai:gpt-4o
```

### 扫描离线 Trace 文件

```bash
agentsec scan langsmith_trace.json -o report.html
agentsec scan claude_code_log.json -o report.md
```

### CI/CD 集成

创建 `.github/workflows/agentsec-scan.yml`：

```yaml
name: AI Agent 安全扫描
on:
  schedule: [{ cron: '0 6 * * *' }]
  workflow_dispatch: {}

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: 运行安全扫描
        uses: nousresearch/agentsec@v1
        with:
          target: hermes
          profile: daily
          fail-on: high
```

## 与竞品对比

| 功能 | agentsec | Garak | Rebuff | Prompt Guard |
|------|:--------:|:-----:|:------:|:------------:|
| 工具调用攻击 | ✅ **18种** | ❌ 仅聊天 | ❌ 仅聊天 | ❌ 仅聊天 |
| MCP 协议攻击 | ✅ 原生 | ❌ | ❌ | ❌ |
| Agent Trace 分析 | ✅ 5种格式 | ❌ | ❌ | ❌ |
| 在线 API 扫描 | ✅ 9个provider | ❌ | ❌ | ❌ |
| CI/CD 集成 | ✅ GitHub Action | ❌ | ❌ | ❌ |
| 自定义攻击模板 | ✅ YAML | ✅ 类似 | ❌ | ❌ |
| 自动修复 | ✅ 4种向量 | ❌ | ❌ | ❌ |
| Agent 仿真 | ✅ 6种模板 | ❌ | ❌ | ❌ |

## 许可证

MIT
