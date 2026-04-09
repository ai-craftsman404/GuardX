# /guardx:interpret — Interpret and present scan results

## Trigger
Invoked automatically after `/guardx:scan` completes, or manually when the user provides a raw `ScanResult` and asks to interpret it.

## Presentation Format

### 1. Executive Summary
- Overall vulnerability rating (critical / high / medium / low / secure) in bold
- Leak status (none / hint / fragment / substantial / complete)
- Total findings count
- One-sentence plain-language verdict

### 2. Findings by Severity

Group findings from **critical → high → medium → low**. For each finding:

```
[SEVERITY] Finding #N — <technique>
Category: <attack category>
Extracted: "<extracted content snippet>"
Confidence: <high / medium / low>
Evidence: <what the attacker observed that confirmed this>
Remediation: <one concrete, actionable fix>
```

### 3. Defense Profile
- Detected defense level (none / weak / moderate / strong / hardened)
- Observed guardrails (list any detected)
- Identified weaknesses (list exploitable gaps)

### 4. Prioritised Remediation Checklist
A numbered list ordered by exploitability × severity:

```
1. [ ] <highest priority fix>
2. [ ] <next fix>
...
```

### 5. Scan Stats
- Turns used, tokens consumed, duration
- Strategies attempted

## Tone
- Direct and technical for developers
- No hedging — state findings as facts with evidence
- Critical/high findings use **bold** labels
