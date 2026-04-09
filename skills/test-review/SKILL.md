# /guardx:test-review — Adversarial Test Review

## Trigger
User invokes `/guardx:test-review <module>` where `<module>` is a module name
(e.g. `probes-extended`) or a test file path (e.g. `mcp-server/tests/unit/probes-extended.test.ts`).

## Purpose
Orchestrates the full adversarial review workflow for a given test file or module.
Uses the two-agent model from `TESTING_ARCHITECTURE.md`:
1. Test Writer (Haiku) writes/refines the test suite
2. Adversarial Evaluator (Sonnet) challenges it on 4 dimensions
3. Loop until all BLOCKER challenges are resolved (max 2 rounds)

## Cost Optimisations

- **Haiku for Test Writer, Sonnet for Evaluator.**
  Test writing is mechanical — generating edge cases, adding boilerplate, fixing known
  patterns. Haiku handles this cheaply. Adversarial reasoning requires Sonnet.

- **Gate on diff — skip unchanged files.**
  Before starting, check `git diff --name-only` for the current branch.
  If the test file has not changed since the last commit, skip the review cycle and
  report: "No changes detected in <file> — review skipped."

- **Test Writer self-checks before calling Evaluator.**
  Before invoking the Evaluator, the Test Writer must verify the file against
  `TESTING_STRATEGY.md` and fix any obvious violations (if-guards, `require()` in ESM,
  type-only assertions). This prevents cheap BLOCKERs from consuming an Evaluator call.

- **Cap at 2 rounds.**
  Round 1 catches real BLOCKERs. Round 2 confirms resolution. If BLOCKERs remain after
  Round 2, escalate to the user with a status report rather than looping further.
  Surface remaining issues as labelled IMPROVEMENTs for the next iteration.

- **Batch related modules.**
  If invoked without a specific module (e.g. `/guardx:test-review`), group all changed
  test files and run one Evaluator pass across the batch rather than one pass per file.

## Steps

1. **Diff check**
   - Run `git diff --name-only` to identify changed test files
   - If `$ARGUMENTS` names a specific file that has not changed, skip and report
   - If no argument given, collect all changed `*.test.ts` files as the batch

2. **Test Writer self-check (Haiku)**
   - Read the test file(s) against `TESTING_STRATEGY.md`
   - Fix any violations found before calling the Evaluator
   - This is a fast pre-filter, not a full review

3. **Adversarial Evaluator review — Round 1 (Sonnet)**
   - Read the test file through the lens of `agents/adversarial-evaluator/AGENT.md`
   - Evaluate on all 4 dimensions: coverage gaps, test quality, implementation
     weaknesses, security logic flaws
   - Produce a structured Challenge Report (format from `TESTING_ARCHITECTURE.md`)
   - Present the full Challenge Report

4. **Test Writer response — Round 1 (Haiku)**
   - For each BLOCKER challenge, apply the fix
   - Do not present proposed changes — apply directly and confirm

5. **Adversarial Evaluator re-review — Round 2 (Sonnet)**
   - Confirm which BLOCKERs were resolved
   - Raise any new BLOCKERs found
   - If none remain, issue "No further challenges" verdict
   - If BLOCKERs remain after Round 2, escalate to user — do not loop again

6. **Final summary**
   - State: "Tests approved. N total tests covering M coverage areas."
   - Confirm: "Ready for implementation."

## Output Format

After each evaluator review round:
```
## Adversarial Evaluation Report
**Module:** <module>
**Round:** <N>

### BLOCKER Challenges
[B1] ...
[B2] ...

### IMPROVEMENT Challenges
[I1] ...

### Summary
<verdict>
```

After "No further challenges":
```
✅ Tests approved for <module>
Total tests: <N>
Coverage: happy path, edge cases, error paths, all enum values, security logic
Ready for implementation.
```

## Notes
- This skill does NOT write implementation files — only reviews and strengthens tests
- After receiving "No further challenges", proceed to write the implementation
- See `TESTING_ARCHITECTURE.md` for the full two-agent model specification
- See `TESTING_STRATEGY.md` for always-on coding standards applied during self-check
