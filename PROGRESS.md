# agentvuln 开发进度 — 2026-06-08

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

### v0.2.2 修复 (2026-06-04)

- [x] 修复 DirectAPITarget 的 function 字段格式（dict→name string）
- [x] 修复 8 处 `'dict' object has no attribute 'lower'` / `sequence item 0: expected str instance` 执行错误
- [x] 增加 LLM Judge JSON 解析的 regex fallback（解决 JSON parse error）
- [x] 添加 `_tool_name()` 防御性提取函数，兼容新旧两种 function 格式

### v0.2.2 实战验证 (2026-06-04)

- [x] 3种真实 agent 扫描：Hermes（3漏洞）、browser-use（3漏洞）、OpenHands（1漏洞）
- [x] COMPARISON.md — 真实架构安全对比报告
- [x] browser-use 泄露 SSH 私钥（最严重发现）
- [x] OpenHands SDK (4/4 vuln) ≠ CLI (0/4 vuln) 发现

### v0.3.0 产品化收尾 (2026-06-06) — Codex 合作轮

- [x] Hermes 解耦: `--hermes-home` 参数, friendly skip
- [x] 新增 tests/: 20 测试 (384 行), 累计 51 测试
- [x] `--fail-on` CI 阈值, action.yml 集成
- [x] UTF-8 兼容, HTML escape 防 XSS
- [x] B1 Docker 一键扫描 (multi-stage, 240MB)
- [x] B2 交互打磨 (进度条/--json/根因建议/耗时追踪)
- [x] B3 模板市场 (template search/install + registry.json)
- [x] PyPI 发布 v0.3.0

### v0.4.1 MCP Server — Agent-to-Agent 分发 (2026-06-08)

- [x] `agentsec/mcp_server.py` — FastMCP server, 6 tools, stdio transport
- [x] `agentsec-mcp` / `agentvuln-mcp` CLI entry points
- [x] 工具: scan_agent / scan_trace / list_attacks / list_profiles / list_templates / get_version
- [x] 本地验证: 51 测试通过 + 5 项 MCP 协议测试
- [x] Hermes config 集成 `mcp_servers.agentvuln`
- [x] 已推送 GitHub

## 待办

- [ ] 重启 Hermes 加载 MCP server
- [ ] PyPI 发布 v0.4.1
- [ ] 发布到 MCP 目录 (modelcontextprotocol/servers)
- [ ] Show HN / 知乎
- [ ] browser-use 真实浏览器扫描
- [ ] GitHub Marketplace Release

## 项目位置

- 代码: `/mnt/d/0Agent/hermes/agentsec/`
- GitHub: `https://github.com/Mikehzp/agentvuln`
- PyPI: `https://pypi.org/project/agentvuln/`
