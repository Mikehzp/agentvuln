# 知乎帖子

## 标题（选一个）：

**A (数据驱动，最吸引人)：**
> 我扫描了 4 个主流 AI Agent（Hermes、OpenHands、browser-use），只找到一个全挡住了攻击的

**B (工具类)：**
> 开源 AI Agent 安全扫描器 agentsec — 专门检测工具调用的漏洞，不是那种只测 prompt injection 的

**C (反差感)：**
> OpenHands CLI 安全全优，但它的 SDK 4/4 全漏 — 安全层在 CLI 层不在 Agent 层

---

## 正文（对应标题 A）：

花了一周时间，写了一个专门针对 **AI Agent 工具调用**的安全扫描器。

为什么做这个？

现在市面上的 LLM 安全工具（Garak、Guardrails、Lakera）基本都盯着 **prompt injection** — 也就是「用户输入里藏恶意指令」。但 AI agent 真正的风险不在聊天里，在**工具调用**里：

- 让 agent 执行 `rm -rf /`
- 让 agent 读 `/etc/shadow` 然后发出去
- 让 agent 泄露自己的 system prompt
- 让 agent 链式调用工具：读数据库 → 发邮件 → 数据就出去了

我用这个扫描器测了 4 个真实的 agent 架构：

| Agent | 扫描方式 | 结果 |
|-------|---------|------|
| **Hermes** | ✅ 真实 API 扫描 | 18 个攻击测出 **3 个漏洞** — 泄露了 ~/.env、执行了 SQL 注入、泄露了 system prompt |
| **OpenHands CLI** | ✅ 实际安装版 | 4 个攻击 **全挡住** ✅ — 包括 SSH 私钥窃取都被识别并拒绝 |
| **OpenHands SDK** | ✅ SDK 直接调用 | 4 个攻击 **全中** 🔴 — CodeActAgent 没有任何安全护栏 |
| **browser-use** | 🟡 源码模板扫描 | 18 个攻击测出 **3 个漏洞** — 泄露 SSH 私钥、执行 SQL 注入 |

最有意思的发现：**OpenHands CLI 是安全的，但它的 SDK 完全不设防。** 安全层在 CLI 的封装层，不在 agent 本身。如果你直接用 SDK 集成，等于裸奔。

项目叫 **agentsec**（PyPI 包名 agentvuln，别搞混了）：

- 18 种攻击向量（prompt injection → 权限提升 → 数据泄露 → MCP 攻击 → 跨会话投毒）
- 在线扫描（调真实 API）+ 离线扫描（分析 trace 文件）
- 6 种 agent 模拟模板（LangChain、Claude Code、Codex CLI 等）
- GitHub Action 一键集成到 CI/CD
- 社区模板市场（可以安装/分享 YAML 攻击模板）
- JSON/MD/HTML 三种报告

```
pip install agentvuln
agentsec scan hermes --profile quick
```

开源 MIT，欢迎 star / PR / 提 issue。

---

GitHub: https://github.com/Mikehzp/agentvuln
PyPI: https://pypi.org/project/agentvuln/
