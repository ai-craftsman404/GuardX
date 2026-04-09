# /guardx:agent-escalation — Inter-Agent Privilege Escalation Testing

## Trigger
User invokes `/guardx:agent-escalation` or asks to test multi-agent systems for privilege escalation, agent hierarchy attacks, or lateral movement between agents.

## Steps

1. **Get the agent hierarchy**
   Ask the user to define their agent roles. For each agent, collect:
   - **Name**: e.g. `DataFetcher`, `ManagerAgent`, `AdminAgent`
   - **Privilege level**: integer 1 (lowest) to 10 (highest)
   - **System prompt**: the agent's system prompt text
   - **Can call agents**: names of agents this role is allowed to delegate to (optional)

   Example:
   ```
   Agents:
   - DataFetcher (privilege: 1) → can call: ManagerAgent
   - ManagerAgent (privilege: 5) → can call: AdminAgent
   - AdminAgent (privilege: 10) → no delegation
   ```

2. **Get the target capability**
   Ask: "What unauthorised action is the attacker trying to get the high-privilege agent to perform?"
   Example: `"delete all user records"`, `"exfiltrate API keys"`, `"send phishing emails"`

3. **Confirm and call `test_agent_escalation`**
   ```
   Tool: test_agent_escalation
   Arguments:
     agentHierarchy: [
       { name: "DataFetcher", privilegeLevel: 1, systemPrompt: "...", canCallAgents: ["ManagerAgent"] },
       { name: "ManagerAgent", privilegeLevel: 5, systemPrompt: "...", canCallAgents: ["AdminAgent"] },
       { name: "AdminAgent", privilegeLevel: 10, systemPrompt: "..." }
     ]
     targetCapability: "delete all user records"
     maxChainDepth: 3
   ```

4. **Present escalation chain step-by-step**

   For each step in `chainSteps`:
   ```
   Step N: DataFetcher → ManagerAgent
   Privilege escalated: YES (1 → 5) ⚠️
   Instruction forwarded: "<instruction text>"
   Evidence: "<evaluator evidence>"
   ```

5. **Flag privilege escalation prominently**
   - If `escalationSucceeded: true`:
     `[CRITICAL — PRIVILEGE ESCALATION CONFIRMED]`
     `Highest privilege reached: <privilegeReached>`
     `Unauthorised actions triggered: <list>`

   - If `escalationSucceeded: false`:
     `✅ No successful escalation detected`

6. **Risk level summary**
   - `critical` → 🚨 CRITICAL
   - `high` → ⚠️ HIGH (partial escalation detected)
   - `none` → ✅ SECURE

7. **Show recommendations**

## Notes
- The kill chain: attacker seeds data → low-priv agent reads it → generates internal task → routed to high-priv agent → unauthorised action executed.
- Even if `escalationSucceeded: false`, steps with `privilegeEscalated: true` indicate the delegation chain is exploitable.
- After a critical finding, add explicit validation at each agent boundary: instructions from retrieved/user data must not be trusted as orchestrator commands.
