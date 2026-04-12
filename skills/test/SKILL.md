# /guardx:test — GuardX Testing Assistant

## Trigger
User invokes `/guardx:test [mode] [target]`

Examples:
- `/guardx:test` — run full unit suite and report
- `/guardx:test run scanner` — run tests for a specific module
- `/guardx:test audit rag` — adversarial quality audit on a test file
- `/guardx:test gaps` — find coverage gaps across all modules
- `/guardx:test nonfunc` — run non-functional tests (performance, boundary, concurrency)
- `/guardx:test diagnose mcp-server/tests/unit/scanner.test.ts` — deep-diagnose a failing test file

## Purpose
Ad-hoc testing assistant for GuardX covering all functional and non-functional testing tasks.
Uses the adversarial two-agent model from `TESTING_ARCHITECTURE.md` on demand.

This skill is for testing work at any time — not tied to the TDD pre-ship gate
(`/guardx:test-review` handles that). Use this skill for:
- Running tests and interpreting failures
- Identifying coverage gaps across the full suite
- Adversarial quality audits on existing test files
- Non-functional test runs (performance, boundary, concurrency, resilience)
- Deep diagnosis of persistent or unclear test failures

## Cost Optimisations
- **Haiku for test runs and reporting.** Mechanical tasks (running tests, summarising
  output, finding file paths) use Haiku.
- **Sonnet for adversarial evaluation.** Gap analysis, security logic challenges,
  and quality audits require Sonnet reasoning.
- **Skip passing modules.** In `gaps` mode, skip modules with zero failures unless
  explicitly auditing quality.
- **Scope to $ARGUMENTS target when given.** Never run the full suite if only
  one module is specified.

---

## Mode: run (default)

**Invocation:** `/guardx:test` or `/guardx:test run [module]`

**Steps:**
1. If `[module]` given, run: `cd mcp-server && npx vitest run tests/unit/<module>.test.ts`
   Otherwise run: `cd mcp-server && npm run test:unit`
2. Parse output — count passing and failing tests
3. For each failing test:
   - Show the test name, expected vs received, and the line in the test file
   - Identify root cause: mock contract mismatch, stale assertion, implementation bug,
     or real regression
4. Produce a summary table:
   ```
   Module              Tests   Pass   Fail   Status
   scanner             42      42     0      ✅
   rag                 38      35     3      ❌  [B: missing env var, mock shape mismatch]
   ```
5. If all pass: confirm total test count and report clean.
6. If any fail: list root causes and ask whether to fix immediately or defer.

**Root cause categories:**
- `MOCK_CONTRACT` — mock doesn't match real module export shape
- `STALE_ASSERTION` — test asserts value that changed in implementation
- `MISSING_ENV` — env var not set before module import
- `REAL_BUG` — implementation returns wrong value — escalate to user

---

## Mode: audit

**Invocation:** `/guardx:test audit [module|all]`

Runs the full adversarial evaluation loop (from `TESTING_ARCHITECTURE.md`) on
an existing test file, outside of the normal TDD pre-ship gate.

Use this when you suspect an existing test file has coverage gaps, weak assertions,
or security logic flaws — without the file being part of an active build.

**Steps:**
1. Identify the test file:
   - If `[module]` given → `mcp-server/tests/unit/<module>.test.ts`
   - If `all` given → batch all `*.test.ts` files in `mcp-server/tests/unit/`
2. **Adversarial Evaluator (Sonnet)** — read the file(s) through the lens of
   `agents/adversarial-evaluator/AGENT.md`, evaluate on all 4 dimensions:
   - Coverage gaps
   - Test quality
   - Implementation weaknesses
   - Security logic flaws
3. Present the Challenge Report (format from `TESTING_ARCHITECTURE.md`)
4. For each **BLOCKER** challenge, ask: "Fix now (Test Writer — Haiku) or log as
   issue for next build session?" Default: fix now if single file, log if batch.
5. If fixing: **Test Writer (Haiku)** applies fixes, then Evaluator re-reviews (max 2 rounds)
6. Issue final verdict: "N BLOCKERs resolved. M IMPROVEMENTs logged."

**Output format:** same Challenge Report format as `/guardx:test-review`.

---

## Mode: gaps

**Invocation:** `/guardx:test gaps [module]`

Identifies untested code paths, missing module test files, and coverage blind spots.

**Steps:**
1. List all source files in `mcp-server/src/` using Glob
2. For each source file, check whether a corresponding test file exists in
   `mcp-server/tests/unit/`
3. For source files WITH a test file:
   - Count exported functions (Grep for `^export`)
   - Check whether each exported function has at least one test (Grep for function name in test)
   - Flag functions with zero test coverage
4. For source files WITHOUT a test file → flag as `NO_TEST_FILE`
5. Run non-functional test files and report:
   - `boundary.test.ts` — boundary value coverage
   - `performance.test.ts` — performance thresholds
   - `concurrency.test.ts` — race condition coverage
   - `canary-resilience.test.ts` — canary token edge cases
6. Produce a gap table:

   ```
   Source file            Test file    Untested exports    Status
   scanner.ts             ✅           0                   Clean
   poisoning.ts           ✅           test_data_poisoning  Partial
   <new-file>.ts          ❌           —                   NO_TEST_FILE
   ```

7. Highlight any `NO_TEST_FILE` entries — these are the highest priority gaps.
8. If `[module]` given, scope gap analysis to that source file only.

---

## Mode: nonfunc

**Invocation:** `/guardx:test nonfunc`

Runs the non-functional test suite and interprets results.

**Non-functional test files in GuardX:**
| File | What it tests |
|---|---|
| `performance.test.ts` | Response time thresholds for all 27 MCP tools |
| `boundary.test.ts` | Extreme input values — empty strings, max-length, Unicode, special chars |
| `concurrency.test.ts` | Parallel scan calls, race conditions, shared state |
| `canary-resilience.test.ts` | Canary token detection under paraphrasing and encoding variations |
| `history-boundary.test.ts` | Scan history file system limits, large history sets |
| `auto-scan-hook.test.ts` | PostToolUse hook trigger correctness |
| `mcp-contract.test.ts` | MCP tool schema contracts — required fields, type enforcement |

**Steps:**
1. Run each file in sequence: `npx vitest run tests/unit/<file>`
2. For each file, report: pass/fail count and any threshold violations
3. For `performance.test.ts` specifically:
   - Show which tools exceeded their response time threshold
   - Flag any tool with >3× its baseline as a **REGRESSION**
4. Present a consolidated non-functional health summary:

   ```
   Non-functional Test Report
   ━━━━━━━━━━━━━━━━━━━━━━━━━━
   performance         ✅  All 27 tools within threshold
   boundary            ✅  No crashes on extreme inputs
   concurrency         ❌  REGRESSION: race condition in scan_system_prompt
   canary-resilience   ✅  All paraphrase variants detected
   history-boundary    ✅
   auto-scan-hook      ✅
   mcp-contract        ✅  All tool schemas valid
   ```

---

## Mode: diagnose

**Invocation:** `/guardx:test diagnose [test-file-path]`

Deep diagnosis of a specific failing or suspect test file.

Use when a test is failing and the root cause isn't obvious from the run output.

**Steps:**
1. Read the test file fully
2. Read the corresponding source file it tests
3. Run the test file in isolation with verbose output:
   `cd mcp-server && npx vitest run <path> --reporter=verbose 2>&1`
4. For each failing test:
   - Check mock contracts against real exports (Grep the source file for export names)
   - Check whether the test uses `vi.mock` at module level (not inside test body)
   - Check whether env vars are set before `vi.resetModules()` + dynamic import
   - Check for `require()` usage in ESM context
   - Check for timezone-sensitive assertions (`getHours()`, specific UTC values)
5. Produce a diagnosis per failing test:

   ```
   Test: "scan_system_prompt returns critical finding"
   Failure: Expected 'critical' received undefined
   Root cause: MOCK_CONTRACT — mock returns `{ severity: 'high' }` but
               scanner.ts ScanFinding uses `{ severityLevel: 'critical' }`
   Fix: Update mock to use `severityLevel` not `severity`
   ```

6. Ask: "Apply all fixes now or show diffs for review?"
   - If applying: Test Writer (Haiku) makes the fixes, then re-runs the file to confirm

---

## Adversarial Evaluator Reference

All `audit` mode evaluation follows `agents/adversarial-evaluator/AGENT.md`.
The four dimensions:

1. **Coverage Gaps** — missing attack scenarios, input combinations, enum values, error paths
2. **Test Quality** — weak assertions, mock-testing-mock, order-dependent tests, exact LLM strings
3. **Implementation Weaknesses** — crash inputs, async edge cases, boundary/off-by-one
4. **Security Logic Flaws** — false negatives, misclassified severity, paraphrase-bypass, canary misses

Always-on rules from `TESTING_STRATEGY.md`:
- No if-guards around assertions (vacuous pass)
- Assert value, not just type
- Structural routing in mocks, not keyword sniffing
- No `require()` in ESM
- Restore env vars in `finally` blocks

---

## Notes

- This skill covers **ad-hoc testing at any time** — before, during, or after a build
- For the **pre-ship TDD gate**, use `/guardx:test-review <module>` instead
- All test files live in `mcp-server/tests/unit/`; integration tests in `mcp-server/tests/integration/`
- Integration tests require `OPENROUTER_API_KEY` and make real API calls — never run in CI without the secret
- Current test count: 849 unit tests across 30 test files (as of v7.0.0)
- Test runner: `npm run test:unit` → Vitest in ESM mode
