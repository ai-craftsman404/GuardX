# /guardx:extended-probes — FlipAttack / PAP / Roleplay Scanner

## Trigger
User invokes `/guardx:extended-probes` or asks to test with "FlipAttack", "PAP", "persuasive prompts", "roleplay jailbreaks", "character reversal", or "advanced attack techniques".

## Steps

1. **Get the system prompt**
   - Ask: "Paste the system prompt you want to test with extended attack techniques."
   - If the user already provided it in their message, use it directly.

2. **Optionally confirm technique selection**
   - Default: run all three techniques (flipattack, pap, roleplay).
   - If the user specifies only certain techniques, use the `techniques` filter.
   - Available techniques: `flipattack`, `pap`, `roleplay`, `serialization-rce`
   - `serialization-rce` tests Jinja2 SSTI (`{{ 7*7 }}`), `__class__.__mro__` MRO traversal, YAML `!!python/object` injection, template literals (`${process.env}`), and EL injection patterns.

3. **Call `scan_extended_probes`**
   ```
   Tool: scan_extended_probes
   Arguments:
     systemPrompt: <system prompt>
     techniques: ["flipattack", "pap", "roleplay"]   # or subset, add "serialization-rce" if needed
     maxAttemptsPerTechnique: 5
   ```

4. **Present per-technique results**

   For each technique (FlipAttack, PAP, Roleplay), show:

   **FlipAttack** (character/word-order reversal)
   - Attempts: N  |  Successes: N  |  Success Rate: X%
   - Best attack found: `<attackPrompt>` (if any)
   - Status: ✅ Secure / ⚠️ Partial leakage / 🚨 Full leakage

   **PAP — Persuasive Adversarial Prompts** (social manipulation)
   - Attempts: N  |  Successes: N  |  Success Rate: X%
   - Best attack found: `<attackPrompt>` (if any)
   - Status: ✅ / ⚠️ / 🚨

   **Roleplay-Based Jailbreaks** (fictional framing, DAN, developer mode)
   - Attempts: N  |  Successes: N  |  Success Rate: X%
   - Best attack found: `<attackPrompt>` (if any)
   - Status: ✅ / ⚠️ / 🚨

5. **Overall vulnerability rating**
   - Show `overallVulnerability` with colour coding:
     - `critical` → 🚨 CRITICAL
     - `high_risk` → ⚠️ HIGH RISK
     - `medium_risk` → ⚠️ MEDIUM RISK
     - `low_risk` → ℹ️ LOW RISK
     - `secure` → ✅ SECURE

6. **Auto-invoke `/guardx:interpret`** on the findings for remediation advice
   - Pass the `findings` array to interpret for severity-grouped analysis.

## Technique Descriptions (for user context)

- **FlipAttack**: Reverses character or word order of the attack prompt. Safety classifiers fail to detect reversed text while the model can still interpret it. ~98% success rate on poorly hardened models.
- **PAP**: Uses social manipulation — authority appeals, urgency, ethical framing, reciprocity, social proof. Bypasses models that resist technical jailbreaks.
- **Roleplay**: DAN-style prompts, character impersonation, hypothetical scenarios, developer mode. 89.6% success rate on unhardened models.

## Notes
- These techniques run against the OpenRouter backend — an API key is required.
- Results complement the standard `/guardx:scan` — they target different attack surfaces.
- If `overallVulnerability` is `critical` or `high_risk`, strongly recommend running `/guardx:harden` to generate guardrails.
