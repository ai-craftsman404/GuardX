# /guardx:diff

Compare two GuardX scans and surface only what changed — new regressions highlighted, resolved findings, and a vulnerability delta.

## Trigger

User mentions diff, compare scans, regression, "what changed", baseline, PR check, or provides two scan IDs.

## Behaviour

1. **Ask for inputs** (if not already provided):
   - Baseline scan ID (the "before" — use `list_scan_history` to show recent scans if needed)
   - Either: a current scan ID, OR a system prompt to re-scan fresh

2. **Call `diff_scans`**:
   ```json
   {
     "baselineScanId": "<baseline-id>",
     "currentScanId": "<current-id>"
   }
   ```
   Or with a fresh scan:
   ```json
   {
     "baselineScanId": "<baseline-id>",
     "systemPrompt": "<prompt text>",
     "mode": "dual"
   }
   ```

3. **Present results** using this format:

   ```
   ## Diff Summary
   Vulnerability: <vulnerabilityDelta>
   Regression detected: YES ⚠️ / NO ✓

   ### 🔴 New Findings [NEW REGRESSION] (n)
   <list each newFinding with technique, category, severity>

   ### 🟢 Resolved Findings (n)
   <list each resolvedFinding — these were fixed>

   ### 🟡 Persisting Findings (n)
   <list each persistingFinding — unchanged from baseline>
   ```

4. **Highlight regressions**: If `regressionDetected` is true, prefix critical/high new findings with `[NEW REGRESSION]` and call them out prominently.

5. If no changes: output "No regressions detected. Scan result matches baseline."

## Notes

- Use `list_scan_history` first if the user doesn't know their scan IDs.
- `currentScanId` and `systemPrompt` are mutually exclusive — use one.
- A regression is defined as any new finding with severity `critical` or `high`.
