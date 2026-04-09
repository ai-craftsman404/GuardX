# /guardx:scan-endpoint — HTTP Endpoint Security Scan

## Trigger
User invokes `/guardx:scan-endpoint` or asks to scan a live API endpoint, deployed chatbot, or HTTP service.

## Steps

1. Ask: "What is the URL of the endpoint to scan? (e.g. https://api.example.com/chat)"

2. Ask: "What does the request body look like? Provide a JSON template with `{{PROBE}}` where the attack probe text should go."

   Show examples:
   - OpenAI-compatible: `{"model":"gpt-4o","messages":[{"role":"user","content":"{{PROBE}}"}]}`
   - Simple chat API: `{"message":"{{PROBE}}"}`
   - LangChain: `{"input":"{{PROBE}}"}`

3. Ask: "Where in the JSON response is the model's reply? (dot-notation path)"

   Common examples:
   - OpenAI: `choices.0.message.content`
   - Simple: `response`
   - Ollama: `message.content`

   Press Enter to use the full response body as-is.

4. Ask: "Do you need any authentication headers? (e.g. `Authorization: Bearer <token>`)"
   - If yes, collect the header name and value.

5. Confirm the configuration with the user, then call the `scan_endpoint` MCP tool:
   ```
   Tool: scan_endpoint
   Arguments:
     url: <endpoint URL>
     requestTemplate: <JSON template with {{PROBE}}>
     responseField: <dot-notation path or omit>
     headers: <auth headers or omit>
     method: "POST"
   ```

6. When the scan completes, automatically invoke `/guardx:interpret` on the result.

## Notes
- The endpoint receives real HTTP requests with attack probes — use only on endpoints you own or have permission to test.
- Scan results are auto-saved to history with a `scanId`.
- For authenticated endpoints, pass the Authorization header in the `headers` parameter.
- Default timeout is 30 seconds per probe request.
