# agentsec 开发进度 — 2026-06-03

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
- [x] `compatibility-matrix.json` — DeepSeek 验证通过 (5/5 quick), 其他 provider 因缺 key 跳过
- [x] self-test 7/7 持续通过

### v0.3.0 开发者产品化 (2026-06-03)

- [x] 修复 pyproject.toml — setuptools License 兼容性问题
- [x] 重写 README.md — 中英文完整文档 + 攻击表 + 架构图 + 竞品对比
- [x] 重新构建 dist（pyproject.toml + README 变更后）
- [x] 打开 PyPI 注册页面待用户完成

## 待办

- [ ] 完成 PyPI 注册 → 配置 `.pypirc` → `twine upload dist/*`
- [ ] 获取更多 API key（OpenAI / OpenRouter / Anthropic）以完成多模型兼容性矩阵
- [ ] 实时运行时监控模式（非定时扫描，而是 hook 进 agent 实际运行时检测）
- [ ] 发布 GitHub Marketplace Release
- [ ] 提取 agentsec 为独立 repo？（决定项目独立性和定位）

## 项目位置

/mnt/d/0Agent/hermes/agentsec/
