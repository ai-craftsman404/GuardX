# GuardX

LLM security scanner as a Claude Code plugin — powered by [ZeroLeaks](https://github.com/ZeroLeaks/zeroleaks).

Scan AI system prompts for prompt injection and extraction vulnerabilities directly from Claude Code. Get structured findings with severity ratings, defense fingerprints, and remediation advice, all interpreted inline.

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

Open Claude Code in the GuardX directory:

```bash
claude --plugin-dir .
```

The `guardx` MCP server starts automatically via `.mcp.json`. Verify with `/help` — you should see `/guardx:scan`, `/guardx:interpret`, and `/guardx:probes`.

---

## Skills

### `/guardx:scan`
Scan a system prompt for vulnerabilities. Paste the prompt directly or provide a file path. Runs in dual mode (extraction + injection) by default.

### `/guardx:interpret`
Present scan findings grouped by severity with remediation steps. Called automatically after `/guardx:scan`.

### `/guardx:probes`
Browse the full attack probe catalogue — 18 categories explained in plain language.

---

## MCP Tools

The MCP server exposes 4 tools directly usable from Claude:

| Tool | Description |
|---|---|
| `scan_system_prompt` | Full vulnerability scan — returns findings, ratings, defense profile |
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

GitHub Actions runs on every push to `main` and every PR:

- Unit tests always run
- Integration tests run only when `OPENROUTER_API_KEY` is set as a repository secret
- A test summary comment is posted to every PR

Set the secret: **Settings → Secrets and variables → Actions → `OPENROUTER_API_KEY`**

---

## Directory Structure

```
GuardX/
├── .claude-plugin/plugin.json     # Plugin manifest
├── mcp-server/
│   ├── src/server.ts              # MCP server — 4 tools
│   ├── tests/
│   │   ├── fixtures/              # AutoGPT system prompt fixtures
│   │   ├── unit/                  # Unit tests (mocked zeroleaks)
│   │   └── integration/           # Integration tests (real OpenRouter)
│   ├── package.json
│   └── tsconfig.json
├── skills/
│   ├── scan/SKILL.md              # /guardx:scan
│   ├── interpret/SKILL.md         # /guardx:interpret
│   └── probes/SKILL.md            # /guardx:probes
├── agents/security-scanner/       # Specialist security agent
├── .github/workflows/guardx-ci.yml
├── .mcp.json                      # Wires Claude Code to MCP server
└── .env.example
```

---

## Roadmap

| Phase | Scope |
|---|---|
| **MVP** (current) | MCP server + core scan skill + basic result output |
| **Phase 2** | Scan history, HTML/SARIF reports, auto-scan hook, specialist agent |
| **Phase 3** | Canary tokens, agentic red teaming, OWASP/NIST mapping, adaptive guardrails, HTTP endpoint targeting |
| **Phase 4** | Deep tool-call exfiltration testing, multi-modal injection, custom HTTP adapters, JUnit XML + SARIF CI/CD formats, differential scanning |
