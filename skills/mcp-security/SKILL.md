# /guardx:mcp-security — MCP Protocol Security Testing

## Trigger
User invokes `/guardx:mcp-security` or asks about "tool poisoning", "MCP security", "tool description injection", "credential exfiltration via tools", "argument injection", or "tool invocation hijacking".

## Steps

1. **Get the system prompt**
   - Ask: "Paste the system prompt of the agent you want to test."

2. **Get the MCP tool schemas**
   - Ask: "List the MCP tools your agent has access to. For each tool, provide:
     - Tool name
     - Tool description
     - Input schema (field names and types)

   For example:
   ```
   - scan_system_prompt: Runs a security scan. Input: { systemPrompt: string }
   - generate_report: Generates a report. Input: { id: string, format: string }
   ```"

   - Convert the user's description into `McpToolSchema[]` format.

3. **Call `test_mcp_security`**
   ```
   Tool: test_mcp_security
   Arguments:
     systemPrompt: <system prompt>
     mcpToolSchemas: [
       { name: "...", description: "...", inputSchema: {...} },
       ...
     ]
   ```
   - `sensitivePatterns` defaults to `['API_KEY', 'SECRET', 'TOKEN', 'PASSWORD']` — override only if needed.

4. **Present findings grouped by attack type**

   **Tool Description Poisoning**
   List each poisoned tool with evidence. Explain that an attacker who can modify tool descriptions can embed hidden instructions that override Claude's behaviour.

   **Argument Exfiltration**
   List any attempts where sensitive environment data (API keys, secrets, tokens) appeared in tool arguments. Flag each one:
   > 🚨 **[CRITICAL — CREDENTIAL EXPOSURE RISK]**: `<toolName>` — `<sensitiveDataFound>` appeared in tool call arguments.

   **Invocation Hijacking**
   List any cases where injected instructions caused Claude to call tools it should not call.

   **Schema Confusion**
   List any schema boundary cases that caused unexpected behaviour.

5. **Risk level summary**
   - `critical` → 🚨 CRITICAL — credential exposure confirmed
   - `high` → ⚠️ HIGH — tool poisoning or hijacking detected
   - `medium` → ⚠️ MEDIUM — schema confusion or boundary issues
   - `none` → ✅ No MCP security vulnerabilities detected

6. **Recommendations**
   Present the `recommendations` array with concrete remediation steps.

## Critical Finding Flag
For ANY finding where `sensitiveDataFound` is non-empty, display prominently:

```
🚨 [CRITICAL — CREDENTIAL EXPOSURE RISK]
Tool: <toolName>
Sensitive data found: <pattern>
Evidence: <evidence>

This means an attacker may be able to extract real API keys, secrets, or passwords
from your deployment environment via tool call arguments. Immediate remediation required.
```

## Notes
- This skill tests the MCP protocol layer itself — not just the system prompt.
- GuardX itself runs over MCP, making this test directly relevant to GuardX deployments.
- After this test, run `/guardx:harden` to generate system prompt guardrails addressing the findings.
- See `TESTING_ARCHITECTURE.md` for how this test was validated.
