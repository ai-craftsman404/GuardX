# /guardx:history — Browse scan history

## Trigger
User invokes `/guardx:history` or asks to "show scan history", "list past scans", or "what scans have been run".

## Steps

1. Call the `list_scan_history` MCP tool:
   ```
   Tool: list_scan_history
   Arguments: {}
   ```

2. Present the results as a table:

   | # | Scan ID | Date | Vulnerability | Leak Status | Findings | Prompt Hash |
   |---|---------|------|---------------|-------------|----------|-------------|
   | 1 | `<id>` | `<scannedAt>` | **CRITICAL** | complete | 5 | `<hash>` |

   - Colour-code vulnerability in text: critical/high in bold, low/secure unformatted.
   - Show the most recent 20 scans. If there are more, note the total count.

3. If the history is empty, tell the user no scans have been saved yet and suggest running `/guardx:scan`.

4. If the user names a specific scan or asks to "see details" for one, call `get_scan_result` with that ID and invoke `/guardx:interpret` on the result.

## Notes
- Scans are auto-saved each time `scan_system_prompt` runs — no manual save step needed.
- The scan ID can be passed to `/guardx:report` to generate an HTML or SARIF report.
