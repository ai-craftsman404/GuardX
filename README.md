<div align="center">

<img src="docs/images/17763508209f02.png" alt="GuardX — LLM Security Scanner" width="100%"/>

# GuardX

### Catch prompt injection and extraction risks before they reach production.

[![GuardX CI](https://github.com/ai-craftsman404/GuardX/actions/workflows/guardx-ci.yml/badge.svg)](https://github.com/ai-craftsman404/GuardX/actions/workflows/guardx-ci.yml)
[![Node.js 20+](https://img.shields.io/badge/Node.js-20%2B-339933?style=flat-square&logo=node.js&logoColor=white)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Claude Code Plugin](https://img.shields.io/badge/Claude%20Code-Plugin-22d3ee?style=flat-square)](https://claude.ai/code)
[![18 Probe Categories](https://img.shields.io/badge/Attack%20Probes-18%20Categories-7c3aed?style=flat-square)](#attack-coverage--18-probe-categories)
[![License: MIT](https://img.shields.io/badge/License-MIT-22d3ee?style=flat-square)](LICENSE)

[**Quick Start**](#quick-start) · [**How It Works**](#how-it-works) · [**Skills**](#skills) · [**Attack Coverage**](#attack-coverage--18-probe-categories) · [**MCP Tools**](#mcp-tools)

</div>

---

## The Problem

Building AI applications means writing system prompts — but system prompts are attack surfaces. Prompt injection, data extraction, and jailbreak attacks can compromise your AI's behaviour, leak confidential instructions, or redirect it entirely.

**GuardX closes the gap between writing a prompt and shipping it.** Scan directly inside Claude Code, get severity-rated findings with defense fingerprints and remediation steps, all inline — no external tooling required.

---

## Quick Start

### 1. Prerequisites

- Node.js 20+
- An [OpenRouter](https://openrouter.ai) API key

### 2. Install dependencies

```bash
cd mcp-server
npm install
```

### 3. Configure your API key

```bash
cp .env.example .env
# Edit .env and set OPENROUTER_API_KEY=sk-or-...
```

### 4. Load the plugin in Claude Code

```bash
claude --plugin-dir .
```

The `guardx` MCP server starts automatically via `.mcp.json`. Verify with `/help` — you should see `/guardx:scan`, `/guardx:interpret`, and `/guardx:probes`.

---

## Demo

<div align="center">
<img src="docs/images/demo.gif" alt="GuardX demo — scanning a vulnerable system prompt" width="95%"/>
</div>

---

## How It Works

<div align="center">
<img src="docs/images/scan-pipeline.svg" alt="GuardX Scan Pipeline: System Prompt → Dual Analysis → 18 Probe Categories → Score &amp; Classify → Findings Report" width="95%"/>
</div>

<br>

| Step | What happens |
|------|-------------|
| **1. System Prompt** | Paste your prompt directly or provide a file path |
| **2. Dual Analysis** | Two scan modes run in parallel: extraction probing and injection probing |
| **3. 18 Probe Categories** | The native scanning engine runs the full attack probe library against your prompt |
| **4. Score & Classify** | Each finding is rated Critical · High · Medium · Low with a defense fingerprint |
| **5. Findings Report** | Results group by severity with inline remediation advice, interpreted by Claude |

---

## Skills

### `/guardx:scan`
Scan a system prompt for vulnerabilities. Paste the prompt directly or provide a file path. Runs in dual mode (extraction + injection) by default.

### `/guardx:interpret`
Present scan findings grouped by severity with remediation steps. Called automatically after `/guardx:scan`.

### `/guardx:probes`
Browse the full attack probe catalogue — 18 categories explained in plain language.

---

## Attack Coverage — 18 Probe Categories

<div align="center">
<img src="docs/images/probe-grid.svg" alt="GuardX 18 probe categories: Prompt Injection, Prompt Extraction, Jailbreak, Role Confusion, Instruction Override, Context Manipulation, Delimiter Injection, Encoding Bypass, Indirect Injection, Tool Exploit, Memory Poisoning, Goal Hijack, Persona Attack, Multi-Turn Escalation, Social Engineering, Output Manipulation, Data Exfiltration, Privilege Escalation" width="100%"/>
</div>

<br>

Each probe category maps to documented adversarial techniques and fires a set of targeted test payloads during a scan. Use `/guardx:probes` to browse the full catalogue with plain-language descriptions.

---

## MCP Tools

The MCP server exposes 33 tools directly usable from Claude:

| Tool | Description |
|------|-------------|
| `scan_system_prompt` | Full vulnerability scan — returns findings, severity ratings, defense profile |
| `list_probes` | Browse probes, optionally filtered by attack category |
| `list_techniques` | Documented attack techniques knowledge base |
| `get_scan_config` | Available models and scan defaults |

---

## Running Tests

### Unit tests (no API key needed)

```bash
cd mcp-server
npm run test:unit
```

### Integration tests (requires `.env` with real API key)

```bash
cd mcp-server
RUN_INTEGRATION=true npm run test:integration
```

---

## CI/CD

GitHub Actions runs on every push to `master` and every PR:

- Unit tests always run
- Integration tests run only when `OPENROUTER_API_KEY` is set as a repository secret
- A test summary comment is posted to every PR

Note: the workflow triggers on `main` and `master` to match the repo default branch.

Set the secret: **Settings → Secrets and variables → Actions → `OPENROUTER_API_KEY`**

---

## Directory Structure

```
GuardX/
├── .claude-plugin/plugin.json     # Plugin manifest
├── mcp-server/
│   ├── src/server.ts              # MCP server — 33 tools
│   ├── tests/
│   │   ├── fixtures/              # AutoGPT system prompt fixtures
│   │   ├── unit/                  # Unit tests (mocked native scanner)
│   │   └── integration/           # Integration tests (real OpenRouter)
│   ├── package.json
│   └── tsconfig.json
├── skills/
│   ├── scan/SKILL.md              # /guardx:scan
│   ├── interpret/SKILL.md         # /guardx:interpret
│   └── probes/SKILL.md            # /guardx:probes
├── agents/security-scanner/       # Specialist security agent
├── docs/images/                   # README visual assets
├── .github/workflows/guardx-ci.yml
├── .mcp.json                      # Wires Claude Code to MCP server
└── .env.example
```

---

## Roadmap

| Phase | Scope |
|-------|-------|
| **MVP** | MCP server + core scan skill + basic result output |
| **Phase 2** | Scan history, HTML/SARIF reports, auto-scan hook, specialist agent |
| **Phase 3** | Canary tokens, agentic red teaming, OWASP/NIST mapping, adaptive guardrails, HTTP endpoint targeting |
| **Phase 4** | Deep tool-call exfiltration testing, multi-modal injection, custom HTTP adapters, JUnit XML + SARIF CI/CD formats, differential scanning |
| **Phase 5** | Extended probes, MCP security, scheduler, PDF reports, agentic compliance |
| **Phase 6** | Promptware kill chain, supply chain scan, RAG security, agent escalation, multimodal injection |
| **Phase 7** | Native scan engine (ZeroLeaks removed), MCP deep audit, extended encoding probes |
| **Phase 8** (current) | Data poisoning detection, agent chain security, cross-provider consistency, audit export, trend dashboard, jailbreak feed |

---

<div align="center">

<img src="docs/images/footer-banner.svg" alt="" width="100%"/>

[Claude Code Docs](https://docs.anthropic.com/claude/docs) · [MCP Protocol](https://modelcontextprotocol.io/) · [Issues](https://github.com/ai-craftsman404/GuardX/issues) · [Releases](https://github.com/ai-craftsman404/GuardX/releases)

*Made with precision*

</div>
