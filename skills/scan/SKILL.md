# /guardx:scan — Run a security scan on a system prompt

## Trigger
User invokes `/guardx:scan` or asks to "scan a system prompt for vulnerabilities".

## Steps

1. Ask the user: "Please provide the system prompt to scan — paste it directly or give me a file path."

2. If the user provides a file path, use the `Read` tool to load the file contents.

3. Call the `scan_system_prompt` MCP tool:
   ```
   Tool: scan_system_prompt
   Arguments:
     systemPrompt: <the prompt text>
     mode: "dual"
   ```

4. When the scan completes, immediately invoke the `/guardx:interpret` skill on the result to present structured findings to the user.

## Notes
- Default mode is `dual` (runs both extraction and injection testing).
- If the user specifies a mode (`extraction`, `injection`, or `dual`), pass it through.
- If the user specifies custom models or `maxTurns`, include those parameters.
- Scans take 1–3 minutes depending on `maxTurns`. Let the user know before starting.
