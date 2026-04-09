# /guardx:report — Generate an HTML, SARIF, JUnit XML, or PDF report

## Trigger
User invokes `/guardx:report` or asks to "generate a report", "export findings", "create an HTML report", "export SARIF for GitHub", "export JUnit XML", or "generate a PDF report".

## Steps

1. Determine the source:
   - If the user provides a scan ID (from `/guardx:history`), use `id`.
   - If the user has a raw scan result in the current conversation, use `result`.
   - If neither, call `list_scan_history` and ask the user to pick a scan.

2. Determine the format:
   - Ask: "Which format?
     - **HTML** — human-readable report, open in a browser
     - **SARIF** — GitHub Security tab / CI integration
     - **JUnit XML** — Jenkins, SonarQube, Azure DevOps
     - **PDF** — leadership briefing or compliance audit sign-off"
   - Default to `html` if the user does not specify.

3. Call the `generate_report` MCP tool:
   ```
   Tool: generate_report
   Arguments:
     id: <scan id>          # if loading from history
     result: <ScanResult>   # if using inline result
     format: "html" | "sarif" | "junit" | "pdf"
   ```

4. Report the output:
   - Tell the user the file path where the report was written.
   - **HTML**: "Open the file in your browser to view the full report."
   - **SARIF**: "Upload this file to GitHub — go to Security → Code scanning → Upload SARIF, or add it to your CI pipeline."
   - **JUnit XML**: "Add this file to your Jenkins/SonarQube/Azure DevOps pipeline as a test result artifact."
   - **PDF**: "Open this file in any PDF viewer. Suitable for leadership briefings and compliance audit sign-off."

## Format Details

### HTML
Self-contained HTML report with:
- Vulnerability rating badge
- Findings with severity colour-coding
- Defense profile
- Recommendations
- Scan stats

### SARIF 2.1.0
Integrates with:
- GitHub Security tab (Code scanning alerts)
- VS Code SARIF Viewer extension
- Jenkins / SonarQube via plugin

### JUnit XML
Integrates with:
- Jenkins (test results trend)
- SonarQube (quality gate)
- Azure DevOps (test publishing)

### PDF
4-section report:
1. Cover page — scan ID, date, overall vulnerability rating
2. Executive Summary — rating, findings by severity, top 3 recommendations
3. Findings Detail — technique, category, severity, extracted content, evidence
4. Remediation Checklist — prioritised `[ ]` items grouped by severity

## Notes
- Reports are saved to `.guardx/reports/` which is gitignored — they stay local.
- Run `/guardx:history` first if you need to find the scan ID.
