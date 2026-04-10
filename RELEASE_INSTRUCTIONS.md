# GuardX — Public GitHub Release Instructions

Use this file in a dedicated Claude Code chat session for every release.
This session's only job: ensure internal docs are git-ignored and push to GitHub.

---

## Purpose of This Session

This is a dedicated release session for GuardX. Its only job is:
1. Ensure internal docs and secrets are excluded from git via .gitignore
2. Push the clean codebase to the public GitHub repo
3. Repeat for every future phase release

**Important:** Do NOT delete internal planning docs from disk. Use .gitignore to
exclude them from git so they remain available locally for future development.

---

## Sanitization Rules (apply before every push)

### Files to GITIGNORE — exclude from git, keep on disk

Add these to `.gitignore` so they are never tracked or pushed:

```
# Secrets
.env
.claude/

# Internal planning docs — keep locally, never push
PLAN.md
PHASE*_SCOPE.md
HANDOVER_*.md
IMPROVEMENTS_PLAN.md

# Build artifacts
node_modules/
dist/
mcp-server/.guardx/
*.js.map
```

If any of these files are already tracked by git, untrack them with:
`git rm --cached <filename>` — this removes them from git without deleting from disk.

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

## SESSION PROMPT — PHASE 7 RELEASE

Open a new Claude Code chat session using **Haiku** model at **low effort**.
Paste this as your first message:

```
GuardX Phase 7 is complete. The working directory is
C:\Users\georg\claude-code-project\GuardX\

Read RELEASE_INSTRUCTIONS.md for the full sanitization rules.

Perform the following steps in order. Stop and report if any step fails.

STEP 1 — Update .gitignore
Open .gitignore and ensure it contains ALL of these entries (add any missing):
  .env
  .claude/
  PLAN.md
  PHASE*_SCOPE.md
  HANDOVER_*.md
  IMPROVEMENTS_PLAN.md
  node_modules/
  dist/
  mcp-server/.guardx/
  *.js.map

STEP 2 — Untrack any newly added internal docs
Run: git ls-files | grep -E "PLAN\.md|PHASE.*_SCOPE\.md|HANDOVER_.*\.md|IMPROVEMENTS_PLAN\.md|\.env|\.claude/"
For each file listed, run: git rm --cached <filename>
This removes them from git without deleting them from disk.

STEP 3 — Verify zero ZeroLeaks references
Run: grep -rn "zeroleaks" . --exclude-dir=node_modules --exclude-dir=.git
This must return zero matches. If any are found, STOP and report before continuing.

STEP 4 — Scan for secrets
Run: grep -rn "sk-or-v1\|OPENROUTER_API_KEY=sk" . \
  --include="*.ts" --include="*.json" --include="*.md" --include="*.yml" \
  --exclude-dir=node_modules --exclude-dir=.git
If any matches are found, STOP and report before continuing.

STEP 5 — Stage and push
  git add -A
  git status   (confirm no internal docs, secrets, or zeroleaks references appear)
  git commit -m "Phase 7: native scan engine, remove zeroleaks dependency, MCP deep audit, promptware kill chain simulator, extended probes"
  git push

STEP 6 — Confirm
Report back:
- Commit hash
- Confirmation zeroleaks is gone: grep -rn "zeroleaks" . --exclude-dir=node_modules --exclude-dir=.git (must be empty)
- Confirmation PLAN.md, PHASE*_SCOPE.md, .env are NOT in git: git ls-files | grep -E "PLAN\.md|SCOPE\.md|\.env" (must be empty)
- Total tracked file count: git ls-files | wc -l

Rules:
- Do NOT delete any .md files from disk — only gitignore them
- Do not push any file containing an API key or zeroleaks reference
- Use Haiku for any subagents
- No confirmation stops between steps — complete all 6 steps then report
```

---

## SESSION PROMPT — FUTURE PHASE RELEASES (Phase 8+)

Open a new Claude Code chat session using **Haiku** model at **low effort**.
Paste this as your first message:

```
GuardX Phase [N] is complete. The working directory is
C:\Users\georg\claude-code-project\GuardX\

Read RELEASE_INSTRUCTIONS.md for the full sanitization rules.

Perform the following steps in order. Stop and report if any step fails.

STEP 1 — Update .gitignore
Open .gitignore and ensure it contains ALL of these entries (add any missing):
  .env
  .claude/
  PLAN.md
  PHASE*_SCOPE.md
  HANDOVER_*.md
  IMPROVEMENTS_PLAN.md
  node_modules/
  dist/
  mcp-server/.guardx/
  *.js.map

STEP 2 — Untrack any newly added internal docs
Run: git ls-files | grep -E "PLAN\.md|PHASE.*_SCOPE\.md|HANDOVER_.*\.md|IMPROVEMENTS_PLAN\.md|\.env|\.claude/"
For each file listed, run: git rm --cached <filename>
This removes them from git without deleting them from disk.

STEP 3 — Scan for secrets
Run: grep -rn "sk-or-v1\|OPENROUTER_API_KEY=sk" . \
  --include="*.ts" --include="*.json" --include="*.md" --include="*.yml" \
  --exclude-dir=node_modules --exclude-dir=.git
If any matches are found, STOP and report before continuing.

STEP 4 — Stage and push
  git add -A
  git status   (confirm no internal docs or secrets appear as staged)
  git commit -m "Phase [N]: [brief description of what was added]"
  git push

STEP 5 — Confirm
Report back:
- Commit hash
- Confirmation that PLAN.md, PHASE*_SCOPE.md, .env are NOT in git:
  run: git ls-files | grep -E "PLAN\.md|SCOPE\.md|\.env"
  (should return nothing)
- Total tracked file count: git ls-files | wc -l

Rules:
- Do NOT delete any .md files from disk — only gitignore them
- Do not push any file containing an API key
- Use Haiku for any subagents
- No confirmation stops between steps — complete all 5 steps then report
```
