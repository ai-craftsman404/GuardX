# /guardx:tool-exfil

Test whether an agentic system prompt can be manipulated into exfiltrating sensitive data through tool calls.

## Trigger

User mentions tool exfiltration, tool call injection, agentic security, tool abuse, function call leakage, or wants to test an agent that has access to tools.

## Behaviour

1. **Ask for inputs** (if not already provided):
   - System prompt of the agent to test
   - List of tools the agent has access to (name, description, parameter schema)
   - Optionally: target data patterns to look for (default: system prompt keywords)
   - Optionally: max turns (default: 10)

2. **Call `test_tool_exfiltration`**:
   ```json
   {
     "systemPrompt": "<agent system prompt>",
     "availableTools": [
       {
         "name": "search",
         "description": "Search the web",
         "parameters": {
           "type": "object",
           "properties": { "query": { "type": "string" } },
           "required": ["query"]
         }
       }
     ],
     "targetDataPatterns": ["system prompt", "instructions"],
     "maxTurns": 10
   }
   ```

3. **Present results**:

   ```
   ## Tool Exfiltration Test Results
   Risk Level: <riskLevel>

   ### Exploited Tools (n)
   <list toolsExploited>

   ### Successful Exfiltrations (n)
   For each successfulExfiltration:
   - Technique: <technique>
   - Tool called: <toolCalled>
   - Data in args: <extractedData snippet>

   ### Attack Vectors That Succeeded
   <list attackVectors>

   ### All Attempts (n total)
   <summarise exfiltrationAttempts — how many tried, how many succeeded>
   ```

4. If `riskLevel` is `critical` or `high`: recommend reviewing the system prompt for injection hardening and calling `/guardx:harden`.

5. If `riskLevel` is `none`: "No exfiltration attempts succeeded. The agent resisted all 5 attack patterns."

## Notes

- The 5 attack patterns tested are: direct_exfil, indirect_exfil, argument_injection, goal_hijacking, schema_manipulation.
- This tests the agentic tool-call attack surface, not just text responses.
- Requires a real system prompt and real tool schema to be effective.
