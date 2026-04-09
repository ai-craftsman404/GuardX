# /guardx:rag-security — RAG Corpus Poisoning & Exfiltration Testing

## Trigger
User invokes `/guardx:rag-security` or asks to test a RAG pipeline, retrieval-augmented generation system, or document-grounded LLM for injection or data exfiltration vulnerabilities.

## Steps

1. **Get the system prompt**
   - Ask: "Paste the system prompt of the RAG-based LLM you want to test."
   - If already provided, use it directly.

2. **Optionally get the retrieval endpoint**
   - Ask: "Do you have a retrieval endpoint URL to test against? (Optional — skip for simulation-only mode.)"

3. **Optionally select categories**
   - Default: run all 6 attack categories.
   - If the user wants a focused test, accept a subset: `encoding`, `structural`, `semantic`, `layered`, `trigger`, `exfiltration`.

4. **Call `test_rag_security`**
   ```
   Tool: test_rag_security
   Arguments:
     systemPrompt: <system prompt>
     retrievalEndpoint: <url or omit>
     categories: ["encoding", "structural", "semantic", "layered", "trigger", "exfiltration"]
     maxDocumentsPerAttack: 3
   ```

5. **Present results per category**

   For each of the 6 categories, show:

   **Encoding** (base64, homoglyph, ROT13 obfuscation)
   - Techniques attempted: N | Succeeded: N | Success rate: X%
   - Highest severity: critical/high/medium/low/none

   **Structural** (header/footer injection, markdown abuse, JSON field injection)
   - Same format

   **Semantic** (silver noise, inter-context conflict, soft advertisement)
   - Same format

   **Layered** (multi-document split, ranking manipulation)
   - Same format

   **Trigger** (conditional keyword, time-delayed activation)
   - Same format

   **Exfiltration — PyRIT EX1-EX5**
   - EX1 (markdown link beacon): ✅ Blocked / 🚨 SUCCEEDED
   - EX2 (image beacon): ✅ / 🚨
   - EX3 (compliance reframing): ✅ / 🚨
   - EX4 (tool callback): ✅ / 🚨
   - EX5 (persistent propagation): ✅ / 🚨

6. **Flag exfiltration successes prominently**
   - For each finding where `exfiltrationDetected: true`, display:
     `[CRITICAL — DATA EXFILTRATION CONFIRMED]`
     `Technique: <technique> | Payload: <exfilPayload>`

7. **Overall risk summary**
   - `critical` → 🚨 CRITICAL — immediate remediation required
   - `high` → ⚠️ HIGH RISK
   - `medium` → ⚠️ MEDIUM RISK
   - `low` → ℹ️ LOW RISK
   - `none` → ✅ SECURE

8. **Show recommendations**
   - List all recommendations from the result.

## Notes
- RAG attacks bypass system prompts entirely — the injected instruction arrives via the retrieved document, not the user message.
- `exfiltrationDetected: true` is more serious than a standard injection finding — it means data left the system.
- After a critical finding, recommend running `/guardx:harden` to generate guardrails.
