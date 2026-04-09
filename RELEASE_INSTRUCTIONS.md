# GuardX — Public GitHub Release Instructions

Use this file in a dedicated Claude Code chat session for every release.
This session's only job: sanitize the working directory and push to GitHub.

---

## BEFORE YOU START — Rotate Your API Key

A live OpenRouter API key was found in `.env` and `.claude/settings.local.json`.
Go to openrouter.ai and rotate it NOW before any git operations.
GitHub scans pushed commits for secrets and publishes them in the audit log
even if you delete the file later.

---

## Sanitization Rules (apply before every push)

### Files to DELETE — never publish these

| File/Directory | Reason |
|---|---|
| `.env` | Contains API key |
| `.claude/` | Local Claude Code harness config with hardcoded user paths and keys |
| `PLAN.md` | Internal planning document |
| `PHASE4_SCOPE.md` | Internal scoping |
| `PHASE5_SCOPE.md` | Internal scoping |
| `PHASE6_SCOPE.md` | Internal scoping |
| `HANDOVER_PHASE5_REMAINING.md` | Internal handover notes |
| `IMPROVEMENTS_PLAN.md` | Internal improvement tracking |
| Any future `PHASE*_SCOPE.md` | Internal scoping for future phases |
| Any future `HANDOVER_*.md` | Internal handover notes |

### .gitignore — must contain all of these

```
.env
.claude/
node_modules/
dist/
mcp-server/.guardx/
*.js.map
```

### Files safe to publish

- `mcp-server/src/` — all TypeScript source files
- `mcp-server/tests/` — all test files and fixtures
- `skills/` — all SKILL.md files
- `agents/` — all AGENT.md files
- `hooks/` — hooks.json
- `.github/workflows/` — CI pipeline
- `README.md`, `CLAUDE.md`, `TESTING_ARCHITECTURE.md`, `TESTING_STRATEGY.md`
- `.mcp.json`, `.env.example`, `.gitignore`
- `mcp-server/package.json`, `mcp-server/tsconfig.json`
- `.claude-plugin/plugin.json`

---

## SESSION PROMPT — INITIAL RELEASE (v6.0.0)

Open a new Claude Code chat session using **Haiku** model at **low effort**.
Paste this as your first message:

```
I need you to handle the public GitHub release of GuardX at
C:\Users\georg\claude-code-project\GuardX\

Read the file RELEASE_INSTRUCTIONS.md in that directory for full context on
what must and must not be published.

Perform the following steps in order. Stop and report if any step fails.

STEP 1 — Delete internal documents
Delete these files (they must not be published):
  PLAN.md
  PHASE4_SCOPE.md
  PHASE5_SCOPE.md
  PHASE6_SCOPE.md
  HANDOVER_PHASE5_REMAINING.md
  IMPROVEMENTS_PLAN.md
Keep all source files, skills, agents, README, CLAUDE.md, and test files.

STEP 2 — Secure secrets
- Delete .env from the working directory
- Delete .claude/ directory from the working directory
- Open .gitignore and confirm it contains: .env, .claude/, node_modules/, dist/,
  mcp-server/.guardx/, *.js.map — add any that are missing

STEP 3 — Scan for secrets
Run this exact command and report all matches:
  grep -rn "sk-or-v1\|api_key\|apikey\|API_KEY=" . \
    --include="*.ts" --include="*.json" --include="*.md" --include="*.yml" \
    --exclude-dir=node_modules --exclude-dir=.git
If any matches are found outside of .env or .claude/ (which are deleted),
STOP and report before continuing.

STEP 4 — Initialise git and push
  git init
  git add -A
  git status   (review — confirm none of the deleted files appear)
  git commit -m "Initial release: GuardX v6.0.0 — LLM security scanner Claude Code plugin"
  gh repo create guardx --public \
    --description "LLM security scanner Claude Code plugin — 25 MCP tools, 19 skills, RAG/agent/supply-chain testing"
  git remote add origin [URL from gh output]
  git push -u origin main

STEP 5 — Add repo topics
  gh repo edit guardx --add-topic "claude-code,llm-security,prompt-injection,mcp,security-scanner,ai-security"

STEP 6 — Confirm completion
Report back:
- Public GitHub repo URL
- Confirmation .env and .claude/ are NOT in the repo (run: git ls-files | grep -E "\.env|\.claude")
- List of files deleted in Step 1
- Total file count: git ls-files | wc -l

Rules:
- Do not push any file containing an API key pattern
- Do not push .env or .claude/ under any circumstances
- Do not push PLAN.md or PHASE*_SCOPE.md
- Use Haiku for any subagents
- No confirmation stops between steps — complete all 6 steps then report
```

---

## SESSION PROMPT — FUTURE PHASE RELEASES

Use the same dedicated Haiku / low effort session. After each new phase completes:

```
GuardX Phase [N] is complete. The working directory is
C:\Users\georg\claude-code-project\GuardX\

Read RELEASE_INSTRUCTIONS.md for sanitization rules.

Then:
1. Delete any new PHASE[N]_SCOPE.md or HANDOVER_*.md files added this phase
2. Verify .gitignore still covers .env, .claude/, node_modules/, dist/, .guardx/
3. Run secret scan: grep -rn "sk-or-v1\|API_KEY=" . --include="*.ts" --include="*.json" --exclude-dir=node_modules
4. Stage and push: git add -A && git commit -m "Phase [N]: [brief description]" && git push
5. Report the commit hash and confirm no secrets pushed
```
