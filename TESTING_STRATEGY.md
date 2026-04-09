# GuardX Testing Strategy

Always-on coding standards for every test file in this project.
See `TESTING_ARCHITECTURE.md` for the two-agent adversarial model and rationale.

---

## Assertion Standards

- **Never use if-guards around assertions.**
  `if (result.findings.length > 0) { expect(...) }` makes the assertion unreachable when
  the collection is empty — the test passes vacuously. Always assert the precondition
  unconditionally first: `expect(result.findings.length).toBeGreaterThan(0)`.

- **Assert the value, not just the type.**
  Prefer `expect(result.recommendations.length).toBeGreaterThan(0)` over
  `expect(Array.isArray(result.recommendations)).toBe(true)`.
  The latter passes even when the array is empty.

- **Assert specific values per input, not just presence.**
  For enum/tag outputs, assert the exact tags expected for a given category input
  (e.g. `tool_exploit` → `OWASP-Agent-04`), not just that the array is non-empty.

- **Cover boundary values explicitly.**
  For numeric thresholds (e.g. successRate > 0.25), write a test at the exact boundary
  (0.25) to document the `>` vs `>=` distinction.

---

## Mock Standards

- **Use structural routing, not keyword sniffing.**
  Route mocks based on message structure (e.g. `body.messages[1].content.startsWith("...")`)
  rather than system prompt keywords (e.g. `includes("evaluator")`).
  Keyword routing breaks silently if the system prompt under test happens to contain the keyword.

- **Never use call-index counters (`callIndex++`) to route mock responses.**
  Call order is fragile — it changes if the implementation adds a new call or reorders calls.
  Route on message content, model, or other structural properties instead.

- **Verify mock call counts for multi-call functions.**
  If a function makes N fetch calls per input item, assert `expect(fetchCallCount).toBe(N)`
  to catch regressions where calls are added or dropped silently.

---

## ESM / Module Standards

- **Never use `require()` inside ESM test bodies.**
  ESM modules throw `ReferenceError: require is not defined` at runtime.
  Always use top-level `import` statements.

- **For env-var-dependent modules, set the env var before `vi.resetModules()` + dynamic import.**
  Pattern:
  ```ts
  process.env.MY_DIR = tmpDir;
  vi.resetModules();
  mod = await import("../../src/module.js");
  ```

- **Always restore env vars in `finally` blocks, not inline.**
  Inline restoration (`process.env.X = prev` after the assertion) is skipped if the
  assertion throws. Use try/finally to guarantee cleanup.

---

## Timezone / Date Standards

- **Never assert `d.getHours()` or `d.getUTCHours()` for specific values in unit tests.**
  Hour assertions are timezone-dependent across CI environments with different `TZ` settings.
  Assert `d.getMinutes()` or test that the result is a valid future ISO date instead.

---

## Coverage Standards

- **Test all enum values, not just the happy path.**
  For functions that branch on an enum (severity, technique, attackType), write at least
  one test per enum value.

- **Test empty inputs explicitly.**
  Functions receiving arrays, strings, or objects should have a test where those are empty
  (`[]`, `""`, `{}`), verifying no crash and a well-defined return value.

- **Test error paths — not just resolutions.**
  Network errors (fetch rejection), invalid inputs, missing required fields, and unknown
  enum values must each have a dedicated test.

- **Test file persistence end-to-end.**
  For functions that write files, read the file back and assert specific field values —
  not just that the file exists.
