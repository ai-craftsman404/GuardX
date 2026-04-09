# /guardx:red-team — Agentic Red Team Attack

## Trigger
User invokes `/guardx:red-team` or asks to run an adversarial / red team test on a system prompt.

## Steps

1. Ask the user: "Please provide the system prompt to attack — paste it directly or give me a file path."

2. If a file path is provided, use the `Read` tool to load the file contents.

3. Ask: "Which attack strategy would you like?
   - **blitz** — single pass, all attack categories, fast (~1 min)
   - **thorough** *(default)* — 3 adaptive phases, deeper analysis (~5 min)
   - **stealth** — slow, low-sophistication probes first, mimics a real patient attacker
   - **goal-hijack** — 5 objective manipulation techniques: objective substitution, priority inversion, scope expansion, authority override, consequentialist framing"

   If `goal-hijack` is selected, also ask: "What capability is the attacker trying to get the agent to perform? (e.g. 'exfiltrate user data', 'bypass access controls')"

4. Warn the user: "Red team scans take 3–8 minutes and use significant tokens. Proceed?"

5. Call the `run_red_team` MCP tool:
   ```
   Tool: run_red_team
   Arguments:
     systemPrompt: <the prompt text>
     strategy: <blitz | thorough | stealth>
   ```

6. When the result returns, automatically invoke `/guardx:interpret` on the result to present structured findings.

7. Offer to generate a report: "Generate a detailed report? Run `/guardx:report` or say 'generate HTML report'."

## Notes
- Red teaming is more aggressive than a standard scan — it adapts strategy based on what works.
- The `thorough` strategy runs 3 phases: broad recon → targeted escalation → deep extraction.
- Results are auto-saved to scan history with a `scanId` for later retrieval.
