# agentvuln 开发进度 — 2026-06-03

## 已完成

### v0.1.0 (2026-06-01)

- [x] CLI: scan / list-sessions / scan-session / self-test
- [x] 14 个攻击用例
- [x] 3 种报告格式: JSON / MD / HTML
- [x] 在线扫描: DirectAPITarget（直接API, 4.5min全量）
- [x] 2层检测管道: ToolAnalysis + LLM Judge
- [x] Auto-fix: system_prompt_leak / data_leak / privilege_escalation / dos_attack
- [x] Scan profiles: quick(5) / daily(8) / full(14)
- [x] Self-test: 7项全通过
- [x] 统一凭据加载: credentials.py

### v0.2.0 (2026-06-02)

**Round 1 — CI/CD + Shell + Watch + YAML Templates + 4 New Attacks**
- [x] `pyproject.toml` — 包描述 + 依赖
- [x] `action.yml` — GitHub composite action
- [x] `.github/workflows/agentsec-scan.yml` — 示例工作流
- [x] `agentsec shell` — 交互式手工测试
- [x] `agentsec watch` — cron 持续监控
- [x] 自定义攻击模板 (YAML) — `--custom-attacks <dir>`
- [x] PyPI 发布准备 — `scripts/publish.sh`
- [x] 4 个新攻击用例: 攻击总数 14 → 18
  - RAG 投毒 / 跨会话记忆污染 / 多 agent 级联攻击 / 工具输出操纵

**Round 2 — 通用 AgentTarget 接口**
- [x] `AgentTarget` 抽象基类
- [x] `DirectAPITarget` 支持指定 provider/model/base_url/api_key
- [x] `resolve_target()` 工厂方法 — 9个预配端点
- [x] 6 个 Agent 模拟模板（langchain-react / claude-code / codex-cli / openai-functions / mcp-agent / default）
- [x] CLI: `--template` / `--list-templates`
- [x] shell 也使用新的 target 系统

**Round 3 — 检测精度 + Agent 集成 + 多模型测试**
- [x] 16/18 攻击的双语 detect_patterns/refusal_patterns 更新
- [x] LLM Judge 改进: 结构化评判标准 + 严重等级规则 + 更长上下文
- [x] Tool call 格式修复: `function.name` → `{name, arguments}` 标准格式（解决 DeepSeek 400 错误）
- [x] `trace_adapters.py` — LangSmith / LangChain / Claude Code / OpenAI trace 适配器
- [x] `compatibility-matrix.json` — DeepSeek 验证通过 (5/5 quick)
- [x] self-test 7/7 持续通过

### v0.3.0 开发者产品化 (2026-06-03)

- [x] 修复 pyproject.toml — setuptools License 兼容性
- [x] 重写 README.md — 中英文完整文档 + 攻击表 + 架构图 + 竞品对比 + badges
- [x] PyPI 发布: `agentvuln` v0.2.0 → v0.2.1
- [x] CLI 别名: `agentsec` + `agentvuln` 均可
- [x] 独立 GitHub 仓库: [Mikehzp/agentvuln](https://github.com/Mikehzp/agentvuln)
- [x] GitHub credentials: token 认证配置完毕
- [x] DNS 绕过: /etc/hosts 配了 github.com 直连 IP
- [x] 全量扫描报告: 18 attacks, 1 vuln found (system_prompt_leak HIGH)
- [x] 每日下载统计 cron job: 每天9点

### v0.2.2 修复 — 2026-06-04

- [x] 修复 DirectAPITarget 的 function 字段格式（dict→name string）
- [x] 修复 8 处 `'dict' object has no attribute 'lower'` / `sequence item 0: expected str instance` 执行错误
- [x] 增加 LLM Judge JSON 解析的 regex fallback（解决 JSON parse error）
- [x] 添加 `_tool_name()` 防御性提取函数，兼容新旧两种 function 格式
- [x] 修复文件: direct_target.py, target.py, judge.py, detector.py, shell.py
- [x] 攻击文件: multi_agent_collusion.py, tool_chain.py, tool_output_manipulation.py

### v0.2.2 实战验证 — 2026-06-04

- [x] 3种真实 agent 扫描：Hermes（3漏洞）、browser-use（3漏洞）、OpenHands（1漏洞）
- [x] COMPARISON.md — 真实架构安全对比报告（仅含真实安装/源码级 agent）
- [x] 发现: SQL注入是所有agent通病, system_prompt_leak 靠显式安全指令可防
- [x] browser-use 泄露 SSH 私钥（最严重发现）
- [x] OpenHands SDK 依赖修复 + 系统 venv 安装成功
- [x] 175 tests total, 7 real vulnerabilities

### v0.2.2 新增 — OpenHands SDK 真实对话扫描 (2026-06-04)

- [x] OpenHands SDK v1.21 `LocalConversation` API 兼容性验证
- [x] `scripts/scan_openhands_sdk.py` — OpenHands SDK CodeActAgent 真实对话扫描脚本
- [x] `scripts/scan_browseruse_real.py` — browser-use 真实 agent 扫描脚本（需桌面环境）
- [x] **重磅发现: OpenHands SDK (4/4 vuln) ≠ CLI (0/4 vuln)** — 安全层在 CLI 层，不在 agent 层
- [x] COMPARISON.md 更新: OpenHands SDK 4/4 漏洞结果 + CLI vs SDK 对比表格

## 待办

- [ ] **发 Show HN / 知乎 — 获取第一批用户反馈**
- [ ] browser-use 真实浏览器扫描（需桌面环境 — Playwright/Chromium）
- [ ] PyPI token 已失效 — 需重新生成
- [ ] GitHub Marketplace Release

## 项目位置

- 代码: `/mnt/d/0Agent/hermes/agentsec/`
- GitHub: `https://github.com/Mikehzp/agentvuln`
- PyPI: `https://pypi.org/project/agentvuln/`
