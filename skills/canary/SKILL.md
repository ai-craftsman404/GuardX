# /guardx:canary — Canary Token Management

## Trigger
User invokes `/guardx:canary` or asks to inject/check/list canary tokens.

## Steps

1. Ask: "Do you want to (a) inject a canary into a system prompt, (b) check if a canary was triggered, or (c) list active canaries?"

2. **(a) Inject a canary:**
   - Ask: "Please provide the system prompt to embed the canary into — paste it directly or give me a file path."
   - If a file path is provided, use the `Read` tool to load the contents.
   - Optionally ask for a label to identify this canary (press Enter to skip for default "unlabelled").
   - Call the `inject_canary` MCP tool:
     ```
     Tool: inject_canary
     Arguments:
       systemPrompt: <the prompt text>
       label: <optional label>
     ```
   - Show the returned `token` prominently and the modified `embeddedPrompt`.
   - Instruct the user: "Deploy the modified prompt shown above. Keep the token `<token>` safe — use it later to check for leakage."

3. **(b) Check if a canary was triggered:**
   - Ask: "Please provide the canary token (e.g. GX-a1b2c3d4)."
   - Ask: "Do you have a scan ID from history, an inline scan result, or shall I run a fresh scan?"
   - If running a fresh scan, invoke `/guardx:scan` first, then use the result.
   - Call the `check_canary` MCP tool:
     ```
     Tool: check_canary
     Arguments:
       token: <the canary token>
       id: <scan ID>   OR   result: <inline scan result>
     ```
   - Report: triggered = LEAKAGE CONFIRMED (the canary token appeared in extracted content), clean = no leakage detected.

4. **(c) List active canaries:**
   - Call `list_canaries`.
   - Display results as a table: Token | Label | Created | Embedding Style.

## Notes
- Canary tokens have the format `GX-[8 hex chars]`.
- Tokens are stored locally under `.guardx/canaries/`.
- A triggered canary is definitive evidence of prompt leakage — escalate immediately.
