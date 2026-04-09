## Testing

- Never use exact string matching against LLM-generated output. Use partial matching,
  `.toContain()`, or regex. LLMs paraphrase — verbatim assertions will be brittle.
- Before running a new test file, verify that every mock matches the real API contract
  of the module it replaces (correct function names, return shape, parameter order).
- When tests fail, fix the root cause — not just the assertion. If the mock is wrong,
  fix the mock; if the source is wrong, fix the source.
- After each batch of changes, run the full suite (`npm run test:unit`) to catch
  regressions early.
- See [TESTING_STRATEGY.md](./TESTING_STRATEGY.md) for adversarial testing coding
  standards (always-on rules that apply to every test file written in this project).

## General Rules

- When asked to explain something, never start planning, scoping, or building until
  the user explicitly says to proceed. Explanation and implementation are separate phases.
- When writing handover notes or any structured document, re-read the user's request
  before finalising and verify every explicitly requested section is present and non-empty.
