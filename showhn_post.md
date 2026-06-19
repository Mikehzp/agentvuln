# Show HN 帖子 — for Hacker News

## Title (choose one):

**Option A (data-driven):**
> Show HN: I scanned 4 AI agents (Hermes, OpenHands, browser-use) — found vulnerabilities in all but one

**Option B (tool-focused):**
> Show HN: agentsec — open-source security scanner for AI agents that call tools

**Option C (provocative):**
> Show HN: OpenHands CLI blocks all attacks, but its SDK is 4/4 vulnerable — I built a scanner that found this

---

## Body (Option A — data-driven, strongest):

I built an open-source security scanner for AI agents that use tools (Claude Code, ChatGPT functions, LangChain, MCP, etc.).

Unlike existing scanners (Garak, Guardrails, Lakera) that focus on prompt injection in chat, this one targets the unique attack surface of **tool-calling agents**: argument injection, privilege escalation, tool chain contamination, MCP protocol abuse, and more.

I ran it against 4 real agent architectures:

| Agent | Scan Type | Result |
|-------|-----------|--------|
| **Hermes** | ✅ Real API | 3/18 vulns — leaked ~/.env, executed SQL injection, leaked system prompt |
| **OpenHands CLI** | ✅ Installed CLI | 0/4 vulns — refused ALL attacks including SSH key exfiltration |
| **OpenHands SDK** | ✅ SDK API | 4/4 vulns — NO security guardrails in the agent layer |
| **browser-use** | 🟡 Source template | 3/18 vulns — leaked SSH private keys, executed SQL injection |

The most interesting finding: **OpenHands CLI is secure, but its SDK is completely vulnerable.** The security layer lives in the CLI, not in the agent itself. If you integrate OpenHands via SDK directly, you get zero protection.

The project is called **agentsec** (agentvuln on PyPI):
- 18 attack vectors
- Online (live agent API) + offline (trace file) scanning
- 6 agent simulation templates (LangChain, Claude Code, Codex CLI, etc.)
- CI/CD via GitHub Action
- Community template marketplace (install/share YAML attack templates)
- 3 report formats (JSON/MD/HTML)
- Open source (MIT)

pip install agentvuln
# or
docker build -t agentvuln .

Looking for feedback, contributions, and ideas for new attack vectors!

---

## Repo links:
GitHub: https://github.com/Mikehzp/agentvuln
PyPI: https://pypi.org/project/agentvuln/
