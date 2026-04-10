# /guardx:mcp-audit — MCP Configuration Audit

## Trigger
User invokes `/guardx:mcp-audit` or asks to audit MCP configuration, check for privilege escalation vulnerabilities, detect tool description poisoning, scan for SSRF patterns, or identify rogue servers.

## Steps

1. **Get the MCP configuration path**
   - Ask: "What is the path to your MCP configuration file? (Usually ~/.claude/mcp.json or similar.)"
   - If provided directly in the message, use it.

2. **Confirm audit scope** (optional)
   - Default: run all checks (privilege model, tool descriptions, SSRF patterns, rogue servers).
   - If the user wants to skip any, set `checkPrivilegeModel` or `checkToolDescriptions` to `false`.

3. **Call `audit_mcp_config`**
   ```
   Tool: audit_mcp_config
   Arguments:
     configPath: <path>
     checkPrivilegeModel: true      # check for wildcard tool permissions
     checkToolDescriptions: true    # check for injected keywords in descriptions
   ```

4. **Present privilege model findings**

   For each finding where a server allows all tools without an explicit allowlist:
   ```
   🔓 Unrestricted Tool Access: <serverName>
   The server allows access to all tools with no allowlist.
   Recommendation: Define an explicit allowlist of trusted tools for this server.
   ```

5. **Present tool description poisoning findings**

   For each finding where tool descriptions contain adversarial keywords:
   ```
   ⚠️ Description Poisoning: <serverName> / <toolName>
   Adversarial keywords detected in tool description.
   Recommendation: Review and sanitize tool descriptions to remove instruction keywords.
   ```

6. **Present SSRF vulnerability findings**

   For any findings related to file:// URIs or /etc/ paths:
   ```
   🚨 [CRITICAL — SSRF VULNERABILITY]
   Server: <serverName>
   Environment variable: <varName>
   Found: <value>
   Recommendation: Remove file:// URIs and absolute paths from environment variables.
   ```

7. **Present rogue server findings**

   For any findings where server names or commands match suspicious patterns:
   ```
   ⚠️ Rogue Server Detected: <serverName>
   Command: <command>
   Recommendation: Verify server authenticity and source before enabling.
   ```

8. **Overall risk summary**
   - `critical` → 🚨 CRITICAL — SSRF or file access vulnerability detected
   - `high` → ⚠️ HIGH RISK — privilege model or tool poisoning issues
   - `medium` → ⚠️ MEDIUM RISK — suspicious server detected
   - `low` → ℹ️ LOW RISK
   - `pass` → ✅ PASS — no MCP security issues detected

9. **Show recommendations**
   Present the recommendations array with concrete remediation steps.

## Attack Vectors Detected

| Finding Type | Attack Vector | Impact |
|--------------|---------------|--------|
| Privilege Model | Server allows `"tools": "*"` | Attacker can call any MCP tool |
| Tool Description Poison | Tool descriptions contain "ignore", "override", "bypass" keywords | Attacker embeds hidden instructions in tool metadata |
| SSRF Pattern | Environment variables contain `file://` or `/etc/` paths | Server-Side Request Forgery, local file access |
| Rogue Server | Server name or command contains "malicious", "backdoor", "trojan" | Attacker-controlled MCP server |

## Notes
- This audit scans the static MCP configuration file — no runtime analysis.
- The audit complements `/guardx:mcp-security` which tests tool poisoning dynamically via prompt injection.
- After remediation, re-run this audit to verify findings are resolved.
