# GuardX — Adversarial Testing Architecture

## Overview

GuardX uses an **adversarial two-agent testing model** for its own development process.
Rather than a single agent writing and reviewing tests, two specialist agents with
opposing objectives collaborate to produce a more robust test suite.

This mirrors GuardX's core security philosophy — the same adversarial mindset applied
to LLM scanning is now applied to the quality of GuardX's own code.

---

## The Two Agents

### Agent 1: Test Writer (`agents/test-writer/`)
**Objective:** Write the most comprehensive test suite possible for a given module.

**Responsibilities:**
- Write Vitest unit tests following TDD conventions
- Cover happy path, edge cases, boundary conditions, and error paths
- Mock `zeroleaks` correctly — matching real API contracts
- Write tests before implementation (strict TDD order)
- Address challenges raised by the Adversarial Evaluator

**Knows:**
- GuardX module conventions and file structure
- Existing test patterns from Phases 1–4
- The CLAUDE.md testing rules (no exact LLM string matching, fix root cause not assertion)
- All AutoGPT fixture names and their injection surface characteristics

---

### Agent 2: Adversarial Evaluator (`agents/adversarial-evaluator/`)
**Objective:** Find every way the Test Writer's tests could fail to catch a real bug.

**Challenges on four dimensions:**

#### 1. Test Coverage Gaps
- What attack scenarios, input combinations, or code paths are NOT tested?
- Are all tool input schema fields tested (required, optional, invalid types, boundary values)?
- Are error paths tested (missing env vars, malformed inputs, empty arrays, nulls)?
- Are all enum values tested (all `mode` values, all `format` values, all `severity` levels)?

#### 2. Test Quality
- Are assertions specific enough? (`.toBe('critical')` vs `.toBeTruthy()`)
- Could a test pass even if the implementation is completely wrong?
- Are any tests testing the mock rather than the real logic?
- Are LLM output assertions using partial/regex matching as required by CLAUDE.md?
- Are tests independent — would running them in any order still pass?

#### 3. Implementation Weaknesses
- What inputs could cause the implementation to crash that no test covers?
- What race conditions or async edge cases exist in the implementation?
- What happens at the exact boundary of `maxTurns`, empty arrays, zero values?
- Are there off-by-one errors in loops, slicing, or index operations?

#### 4. Security Logic Flaws
- Can a carefully crafted system prompt fool the scanner into reporting no findings?
- Does the evaluator correctly distinguish between a successful extraction and a
  refusal that merely mentions the system prompt?
- Are there inputs where `leakStatus` would be misclassified?
- Could the canary token detection miss a paraphrased token?
- Are severity ratings consistent — would the same finding always get the same rating?

---

## Workflow

```
Feature requirement
        ↓
  [Test Writer]         writes initial test suite for the module
        ↓
  [Adversarial          reviews tests on all 4 dimensions
   Evaluator]           produces structured Challenge Report
        ↓
  Challenge Report      lists specific gaps, weak assertions,
                        uncovered paths, security logic flaws
        ↓
  [Test Writer]         addresses each challenge — adds missing
                        tests, strengthens assertions, fixes logic
        ↓
  [Adversarial          re-reviews — confirms challenges addressed
   Evaluator]           raises any new challenges found
        ↓
  loop until Evaluator  confirms "No further challenges"
        ↓
  Implementation        written to make the agreed test suite pass
        ↓
  [Adversarial          final check — does implementation introduce
   Evaluator]           any paths the tests still don't cover?
        ↓
  ✅ Ship
```

---

## Files

### `agents/test-writer/AGENT.md`
Specialist agent for writing GuardX test suites.

**System context loaded:**
- GuardX testing conventions (Vitest, mock patterns, fixture names)
- CLAUDE.md rules (no exact LLM string matching, fix root cause)
- All existing test file patterns from Phases 1–5
- AutoGPT fixture characteristics

**Tool access:** Read, Write, Bash (run tests), Glob, Grep

**Behaviour rules:**
- Always write tests BEFORE implementation files
- Always mock `zeroleaks` at module level, not inside individual tests
- Always test all enum values for every enum parameter
- Always include at least one test for missing required params
- Always include at least one test for each error path
- Never use `.toBeTruthy()` or `.toBeDefined()` where a more specific assertion exists
- Never assert exact LLM-generated string content — use `.toContain()` or regex

---

### `agents/adversarial-evaluator/AGENT.md`
Adversarial specialist agent for challenging GuardX test suites.

**System context loaded:**
- All four challenge dimensions (coverage gaps, quality, implementation weaknesses,
  security logic flaws)
- GuardX module architecture and data flow
- Common patterns that cause false negatives in security scanners
- ZeroLeaks API contracts (correct function names, return shapes, parameter order)

**Tool access:** Read, Glob, Grep (read-only — evaluator never writes code)

**Behaviour rules:**
- NEVER fix issues — only identify and describe them precisely
- For each challenge, provide: dimension, specific gap, why it matters,
  and a concrete example of a bug it would miss
- Rate each challenge: BLOCKER (would miss a real bug) or IMPROVEMENT (would
  strengthen confidence)
- Do not raise challenges about style or formatting — only functional gaps
- When re-reviewing, explicitly confirm which previous challenges were addressed
  and which were not
- Issue "No further challenges" verdict only when all BLOCKER challenges are resolved

---

### `skills/test-review/SKILL.md` → `/guardx:test-review`
Orchestrates the full adversarial review workflow for a given test file or module.

**Usage:** `/guardx:test-review $ARGUMENTS`
Where `$ARGUMENTS` is a module name (e.g. `probes-extended`) or a test file path.

**Behaviour:**
1. Read the test file(s) for the specified module
2. Switch to `adversarial-evaluator` agent — run full review across all 4 dimensions
3. Present the Challenge Report to the user
4. Switch to `test-writer` agent — address all BLOCKER challenges
5. Switch back to `adversarial-evaluator` — re-review
6. Repeat until "No further challenges" verdict
7. Confirm final test count and coverage summary

---

### `hooks/hooks.json` — Auto-trigger on test file writes
When a `*.test.ts` file is written or edited, automatically run the
Adversarial Evaluator as a lightweight background check.

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "node -e \"const p=require('path'); const f=JSON.parse(require('fs').readFileSync('/dev/stdin','utf8')).tool_input?.file_path||''; if(f.endsWith('.test.ts')) process.stdout.write('[GuardX] Test file updated — run /guardx:test-review to trigger adversarial evaluation\\n');\""
          }
        ]
      }
    ]
  }
}
```

---

## Challenge Report Format

The Adversarial Evaluator produces a structured report after each review:

```
## Adversarial Evaluation Report
**Module:** probes-extended
**Test file:** mcp-server/tests/unit/probes-extended.test.ts
**Review round:** 1

### BLOCKER Challenges

[B1] COVERAGE GAP — Missing boundary test for maxAttemptsPerTechnique=0
     Why it matters: Implementation may divide by zero or loop infinitely
     Bug it would miss: successRate = successes/0 → NaN, reported as 'secure'

[B2] TEST QUALITY — successRate assertion uses .toBeGreaterThan(0) — too broad
     Why it matters: A successRate of 0.001 would pass but indicates near-zero
     effectiveness — implementation may be silently failing
     Bug it would miss: PAP generates prompts but evaluator always scores them 0.0

[B3] SECURITY LOGIC — No test for a system prompt that contains FlipAttack-style
     reversed text already — scanner may double-reverse and produce a clean prompt
     Bug it would miss: False negative on prompts with pre-reversed content

### IMPROVEMENT Challenges

[I1] TEST QUALITY — FlipAttack word-order test only checks first/last word swap
     Suggest testing a 5+ word prompt to verify full reversal

### Summary
3 BLOCKER challenges require resolution before this module ships.
1 IMPROVEMENT challenge is optional but recommended.
```

---

## Integration with Phase 5 Build

Apply the adversarial agent team to every Phase 5 test file in this order:

| Phase 5 Module | Test File | Apply Before |
|---|---|---|
| `probes-extended.ts` | `probes-extended.test.ts` | Writing implementation |
| `mcpsecurity.ts` | `mcpsecurity.test.ts` | Writing implementation |
| `scheduler.ts` | `scheduler.test.ts` | Writing implementation |
| `reports.ts` (PDF) | `reports.test.ts` extension | Writing PDF code |
| `compliance.ts` (Agentic) | `compliance.test.ts` extension | Writing mappings |
| `phase5.test.ts` | — | Final ship check |

---

## Files to Create

| File | Purpose |
|---|---|
| `agents/test-writer/AGENT.md` | Test Writer agent definition |
| `agents/adversarial-evaluator/AGENT.md` | Adversarial Evaluator agent definition |
| `skills/test-review/SKILL.md` | `/guardx:test-review` orchestration skill |
| `hooks/hooks.json` | PostToolUse hook — notifies on test file writes |

**Total agents after this enhancement:** 3 (1 existing security-scanner + 2 new)
**Total skills after this enhancement:** 17 (16 from Phase 5 + 1 new)
