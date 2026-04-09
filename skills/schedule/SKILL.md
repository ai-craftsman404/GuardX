# /guardx:schedule — Automated Scheduled Scanning

## Trigger
User invokes `/guardx:schedule` or asks about "scheduled scan", "automatic re-scan", "cron scan", "recurring scan", "set up automated scanning", or "daily scan".

## Steps

### Listing existing schedules
If the user asks to "list", "show", or "view" schedules:

1. Call `list_scheduled_scans`
2. If no schedules exist, say: "No scheduled scans registered yet. Use `/guardx:schedule` to create one."
3. Otherwise, display as a table:

   | Name | Cron | Last Run | Next Run | Last Result | Status |
   |---|---|---|---|---|---|
   | Production chatbot | 0 9 * * * | 2026-04-04T09:00Z | 2026-04-05T09:00Z | ✅ clean | active |

### Creating a new schedule

1. **Prompt source** — ask:
   "Where is the system prompt?
   - **inline** — paste it here
   - **file** — provide a file path (e.g. `/path/to/prompt.txt`)"

2. **Scan frequency** — ask:
   "How often should this scan run?
   - daily (every day at 9am) → `0 9 * * *`
   - weekly (every Monday at 9am) → `0 9 * * 1`
   - custom cron expression (5 fields, e.g. `*/30 * * * *`)"

3. **Webhook** (optional) — ask:
   "Should we notify a webhook URL when a regression is detected? If yes, provide the URL."

4. **Severity threshold** — ask:
   "Which severity levels should trigger the webhook notification?
   - critical + high (default)
   - critical only
   - all (critical, high, medium, low)
   - custom selection"

5. **Confirm and create** — call `create_scheduled_scan`:
   ```
   Tool: create_scheduled_scan
   Arguments:
     name: <user-provided label>
     systemPrompt: <inline text>   OR   promptFile: <file path>
     cronExpression: <cron string>
     webhookUrl: <url or omit>
     webhookOnSeverity: <array or omit for default>
   ```

6. **Confirm creation** — show:
   ```
   ✅ Scheduled scan created
   ID: <scheduleId>
   Name: <name>
   Schedule: <cronExpression> (plain-English interpretation)
   Next run: <nextRunAt>
   Webhook: <url or 'none'>
   ```

### Deleting a schedule
If the user asks to "delete", "remove", or "cancel" a schedule:

1. If no ID provided, call `list_scheduled_scans` and ask which one to delete.
2. Call `delete_scheduled_scan` with the `scheduleId`.
3. Confirm: "Schedule `<name>` deleted."

## Webhook Payload (for reference)
When a regression is detected, the webhook receives:
```json
{
  "event": "regression_detected",
  "scheduleId": "...",
  "scheduleName": "Production chatbot daily scan",
  "regressionCount": 2,
  "newFindings": [...],
  "scanId": "...",
  "scannedAt": "2026-04-05T09:00:00Z",
  "reportUrl": ".guardx/reports/{id}.html"
}
```

## Notes
- Schedule files are stored in `.guardx/schedules/` as JSON files.
- The cron runner reads these on startup (`node-cron`).
- Use `/guardx:diff` to manually compare two scans if you need an ad-hoc regression check.
- Webhook fires only for severity levels in `webhookOnSeverity` (default: critical + high).
