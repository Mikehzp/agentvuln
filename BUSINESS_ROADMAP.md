# agentvuln 商业化路线图: 45 → 70

## 目标：让一个技术好的陌生人 `pip install` 后，第 5 分钟就能信任结果

| 阶段 | 目标分 | 核心命题 |
|------|--------|---------|
| 🅰 地基 | 45→55 | 结果可信吗？ |
| 🅱 体验 | 55→65 | 上手快吗？集成轻松吗？ |
| 🅲 交付 | 65→70 | 能给别人用吗？ |

---

## 🅰 地基 (45→55) — 让结果可信

### A1. 测试覆盖大补 (3/10 → 7/10)

**现状：** 20 测试 / 6945 行代码 = 2.8 test/kLoC

**目标：** 每 200 行至少 1 个测试 ≈ 35+ 测试 / 70% 核心模块覆盖

来 15 个新测试：

| 模块 | 当前 | 要加 | 测什么 |
|------|------|------|--------|
| Attack 模块 | 3 个集成测试 | +2 个单元测试 | 每种攻击返回的 AttackResult 字段完整、severity 不越界 |
| target.py | 0 | +3 | resolve_target 工厂方法、错误处理、9 个预配端点 |
| fixer.py | 3 | +2 | 修复验证回环、fix 后攻击不再生效 |
| judge.py | 4 | +2 | 不同 LLM 返回格式、极端长输出 |
| shell.py | 2 | +1 | 未完成的交互路径 |
| db.py | 2 | +2 | 并发读、数据一致性 |
| cli.py | 3 | +3 | main() 整合测试、--version、非法参数 |

**指标：** `pytest —cov=agentsec —cov-fail-under=50`

### A2. 检测精度大修 (5/15 → 10/15)

**核心问题：** LLM-as-Judge 不稳定。

**方案：**
1. **加确定性规则引擎** — 对所有 18 种攻击，写静态 pattern matching（正则 / AST），先过规则再走 LLM
2. **Judge 支持多轮投票** — 跑 3 次 LLM 调用，取多数决（仅对 "vulnerable" 判定启用，减少 token 成本）
3. **加 `benchmark.yml`** — 已知通过的案例集，CI 必跑，防止回归

### A3. 补文档 (6/10 → 8/10)

- API 文档（Python 模块注释 + sphinx/readthedocs 配置）
- 集成指南（hermes / langchain / openai / custom）
- 实战案例 README（2-3 个真实扫描报告截图）

---

## 🅱 体验 (55→65) — 让上手无缝

### B1. Docker 一键扫描

```bash
docker run -e API_KEY=xxx agentvuln scan hermes
```

- 内置各 provider 的 API 调用脚本
- 不用装 Python / venv

### B2. 交互体验打磨

- `agentsec scan --json` 输出机器可读
- `agentsec scan --watch` 添加（区别于 watch 子命令）
- 扫描进度条（tqdm 已依赖）
- 失败的根本原因建议（不是 "detected system_prompt_leak"，而是 "你的 system prompt 开头有 'You are an AI assistant'，许多 LLM 会原样重复"）

### B3. 模板市场

- 内置 6 个模板 → 社区贡献模板格式
- `agentsec template search` / `template install`

---

## 🅲 交付 (65→70) — 让企业能用

### C1. SaaS API

```
POST /v1/scan
{"target": "hermes", "profile": "quick"}
→ {"report_id": "xxx", "findings": [...]}
```

- 不需要用户装 CLI
- 结果可分享链接

### C2. 稳定版本 + 发行

- 正式 v1.0.0 发布
- GitHub Release with changelog
- Homebrew / apt 包

### C3. 企业安全报告

- PDF 格式（非 HTML）
- CVE 编号格式的漏洞 ID
- 合规映射（OWASP Top 10 for LLM）

---

## 预估工时

| 阶段 | 工作量 | Codex 能做的 |
|------|--------|-------------|
| A1 测试 | 3-5 天 | ✅ 最擅长的 |
| A2 检测 | 5-10 天 | 🟡 需要设计方向 |
| A3 文档 | 2-3 天 | ✅ |
| B1 Docker | 1 天 | 🟡 |
| B2 体验 | 3-5 天 | ✅ |
| B3 模板 | 3 天 | 🟡 |
| C1 SaaS | 3-4 周 | ❌ 需要后端 |
| C2 发行 | 1 天 | ✅ |
| C3 报告 | 3 天 | 🟡 |

**想让 Codex 从 A1 开始？（地基层，你最关心测试覆盖）**
