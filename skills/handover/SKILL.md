# /guardx:handover — Generate a complete session handover note

## Trigger
User invokes `/guardx:handover` or asks to "write a handover note" / "end the session".

## Steps

1. Read the current test count by running:
   `cd mcp-server && npm run test:unit 2>&1 | tail -5`

2. Run `git diff --stat` and `git status` to identify all files changed this session.

3. Write the handover note to `HANDOVER.md` in the project root with ALL of these
   sections — do not skip any:

   ```
   # GuardX Session Handover — <today's date>

   ## What Was Completed
   - List every feature, fix, or test category added this session
   - Files changed (from git diff --stat)
   - Test count: <previous> → <current> passing

   ## Known Issues & Workarounds
   - Any Windows/MCP/path quirks discovered
   - Any tests that are intentionally skipped and why
   - Any mocks that differ from real API behaviour

   ## Token Efficiency Notes for Next Session
   - Always read a file before editing it (Read before Edit)
   - Use Haiku model for subagents doing research/exploration
   - Batch independent file writes in parallel tool calls
   - Avoid re-reading files already read in same turn

   ## Next Phase — Specific Tasks
   - List concrete next steps with file paths where relevant
   - Note any scoped-but-not-started work

   ## Architecture Decisions Made
   - Document any non-obvious choices and the rationale
   ```

4. After writing, re-read `HANDOVER.md` and verify all 5 sections are present
   and non-empty. If any section is missing or empty, fix it immediately before
   reporting done.

5. Report the handover note path and a one-line summary of what was completed.

## Notes
- Never skip the re-read verification step (step 4).
- The "Token Efficiency Notes" section must always be included verbatim — do not
  summarise or omit it even if no new notes were added this session.
