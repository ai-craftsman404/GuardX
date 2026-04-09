# /guardx:supply-chain — LLM Supply Chain Security Scanner

## Trigger
User invokes `/guardx:supply-chain` or asks to scan for supply chain vulnerabilities, check LLM dependencies for CVEs, detect embedded API keys/secrets, or analyse LoRA adapter files for backdoors.

## Steps

1. **Get the project path**
   - Ask: "What is the path to your project root? (Should contain package.json or requirements.txt.)"
   - If provided directly in the message, use it.

2. **Optionally get LoRA adapter paths**
   - Ask: "Do you have any LoRA adapter weight files to scan for backdoors? (Optional — provide file paths.)"

3. **Confirm scan options** (optional)
   - Default: run all three checks (CVE scan, secret detection, backdoor detection).
   - If the user wants to skip any, set `checkCves`, `checkSecrets`, or `checkBackdoors` to `false`.

4. **Call `scan_supply_chain`**
   ```
   Tool: scan_supply_chain
   Arguments:
     projectPath: <path>
     scanLoraAdapters: [<adapter paths>]  # if provided
     checkCves: true
     checkSecrets: true
     checkBackdoors: true
   ```

5. **Present CVE findings**

   For each CVE finding:
   ```
   📦 <package> v<installedVersion> — <cveId> [CRITICAL/HIGH/MEDIUM/LOW]
   <description>
   Fix: upgrade to v<fixVersion>
   ```

   Flag critical CVEs:
   `[CRITICAL — PATCH IMMEDIATELY]`

6. **Present secret findings**

   For each secret finding:
   ```
   🔑 <file>:<lineNumber> — <secretType> [CRITICAL/HIGH]
   Pattern matched: <pattern>
   ```

7. **Present backdoor findings**

   For each backdoor finding:
   ```
   ⚠️ <adapterFile> — <anomalyType> [CRITICAL/HIGH/MEDIUM]
   Confidence: <confidence * 100>%
   <description>
   ```

8. **Overall risk summary**
   - `critical` → 🚨 CRITICAL — immediate action required
   - `high` → ⚠️ HIGH RISK
   - `medium` → ⚠️ MEDIUM RISK
   - `low` → ℹ️ LOW RISK
   - `none` → ✅ SECURE — no issues found

9. **Show recommendations**

## Known CVEs Checked

| CVE | Package | Severity | Description |
|-----|---------|----------|-------------|
| CVE-2026-33634 | litellm | CRITICAL | Supply chain backdoor (CVSS 9.4) |
| CVE-2026-35030 | litellm | CRITICAL | JWT auth bypass |
| CVE-2025-68664 | langchain | HIGH | Jinja2 SSTI / RCE (CVSS 9.3) |
| CVE-2024-34359 | torch | HIGH | Pickle deserialization RCE |
| CVE-2024-5187 | onnx | HIGH | Path traversal |

## Notes
- Secret findings always warrant immediate credential rotation — even if not yet exploited.
- LoRA backdoor detection uses weight-space anomaly analysis (PEFTGuard-inspired) — no model execution required.
- High singular value concentration (>80% energy in top SV) is the primary backdoor indicator.
