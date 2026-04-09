# /guardx:compliance — OWASP / NIST / MITRE ATLAS / EU AI Act / Agentic Top 10 Mapping

## Trigger
User invokes `/guardx:compliance` or asks to map findings to OWASP LLM Top 10, NIST AI RMF, MITRE ATLAS, EU AI Act, or OWASP Agentic Top 10.

## Steps

1. Ask: "Do you have a scan ID from history, an inline scan result, or shall I run a fresh scan first?"
   - If running a fresh scan, invoke `/guardx:scan` first, then use the result.

2. Call the `map_findings` MCP tool:
   ```
   Tool: map_findings
   Arguments:
     id: <scan history ID>   OR   result: <inline ScanResult>
   ```

3. Present a compliance table:

   **OWASP LLM Top 10 2025 — Triggered Controls**
   | OWASP ID | Name | Findings |
   |---|---|---|
   | LLM01 | Prompt Injection | N findings |
   | LLM02 | Sensitive Information Disclosure | N findings |
   | LLM06 | Excessive Agency | N findings |

   **OWASP Agentic Top 10 2026 — Triggered Controls**
   | ID | Name | Findings |
   |---|---|---|
   | OWASP-Agent-01 | Excessive Agency | N findings |
   | OWASP-Agent-02 | Prompt Injection | N findings |
   | OWASP-Agent-04 | Insecure Tool Use / Tool Poisoning | N findings |
   | ... | ... | ... |

   **NIST AI RMF — Implicated Categories**
   List each unique NIST category (e.g. GOVERN 1.1, MEASURE 2.5) and why it applies.

   **MITRE ATLAS — Relevant Tactics**
   List each ATLAS tactic (e.g. AML.T0051, AML.T0054) and the attack category that triggered it.

   **EU AI Act — Implicated Articles**
   List each Article (e.g. Article 9, Article 13, Article 15) and which findings apply.

4. For each triggered OWASP LLM ID, explain in plain language:
   - **LLM01 — Prompt Injection**: Attackers can manipulate the model's instructions via crafted inputs.
   - **LLM02 — Sensitive Information Disclosure**: The model may reveal confidential system prompt content.
   - **LLM06 — Excessive Agency**: The model may take actions beyond its intended scope.

5. For key OWASP Agentic Top 10 IDs, explain:
   - **OWASP-Agent-02 — Prompt Injection**: The agent's instructions can be overridden by adversarial inputs.
   - **OWASP-Agent-04 — Insecure Tool Use / Tool Poisoning**: Tool descriptions or arguments can be exploited to manipulate agent behaviour.
   - **OWASP-Agent-05 — Unsafe Agentic Patterns**: The agent exhibits patterns that enable adversarial manipulation.
   - **OWASP-Agent-06 — Information Leakage**: Agent reveals sensitive internal configuration or data.

6. End with a summary:
   > "This scan implicates **N** OWASP LLM Top 10 controls, **M** OWASP Agentic Top 10 controls, **P** NIST AI RMF categories, **Q** MITRE ATLAS tactics, and **R** EU AI Act articles."

## Frameworks Covered

| Framework | Version | Purpose |
|---|---|---|
| OWASP LLM Top 10 | 2025 | LLM-specific vulnerability taxonomy |
| OWASP Agentic Top 10 | 2026 | Agentic AI vulnerability taxonomy (newest) |
| NIST AI RMF | 1.0 | AI risk management framework |
| MITRE ATLAS | Current | ML-specific adversarial tactic framework |
| EU AI Act | 2024 | EU regulatory compliance |

## Notes
- Each finding is tagged with relevant framework IDs based on its attack category and severity.
- The OWASP Agentic Top 10 2026 is the newest framework, published December 2025.
- Use `/guardx:harden` after this to generate prompt hardening text for the identified vulnerabilities.
