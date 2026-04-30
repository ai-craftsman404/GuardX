import * as fs from "fs";
import * as path from "path";
import type { ScanFinding } from "./scanner.js";

export interface AuditReportResult {
  reportPath: string;
  framework: "soc2" | "iso27001" | "nist-ai-rmf" | "all";
  controlsMapped: number;
  controlsFailed: number;
  executiveSummary: string;
}

interface ControlMapping {
  id: string;
  name: string;
  description: string;
}

const SOC2_CONTROLS: Record<string, ControlMapping> = {
  "CC6.1": {
    id: "CC6.1",
    name: "Access Control",
    description: "Logical and physical access controls over IT infrastructure",
  },
  "CC6.6": {
    id: "CC6.6",
    name: "External Threat Management",
    description: "Protection against external threats",
  },
  "CC7.2": {
    id: "CC7.2",
    name: "System Monitoring",
    description: "System monitoring and detection of anomalies",
  },
  "CC8.1": {
    id: "CC8.1",
    name: "Change Management",
    description: "Configuration changes and version control",
  },
};

const ISO27001_CONTROLS: Record<string, ControlMapping> = {
  "A.5.23": {
    id: "A.5.23",
    name: "Cloud Security",
    description: "Information security in cloud service arrangements",
  },
  "A.8.24": {
    id: "A.8.24",
    name: "Cryptography",
    description: "Cryptographic controls and key management",
  },
  "A.8.28": {
    id: "A.8.28",
    name: "Secure Coding",
    description: "Secure development and testing practices",
  },
};

const NIST_AI_RMF_CONTROLS: Record<string, ControlMapping> = {
  "GOVERN-1.1": {
    id: "GOVERN-1.1",
    name: "AI Governance",
    description: "Governance structures for AI systems",
  },
  "MAP-1.5": {
    id: "MAP-1.5",
    name: "Risk Mapping",
    description: "Risk mapping for AI systems",
  },
  "MEASURE-2.5": {
    id: "MEASURE-2.5",
    name: "Performance Measurement",
    description: "Measurement and monitoring of AI performance",
  },
  "MANAGE-2.4": {
    id: "MANAGE-2.4",
    name: "Risk Management",
    description: "Risk management and mitigation",
  },
};

export async function generateAuditReport(
  findings: ScanFinding[],
  framework: "soc2" | "iso27001" | "nist-ai-rmf" | "all",
  format: "json" | "html" | "csv",
  organizationName?: string,
  outputPath?: string
): Promise<AuditReportResult> {
  const baseDir = outputPath || path.join(process.cwd(), ".guardx");
  if (!fs.existsSync(baseDir)) {
    fs.mkdirSync(baseDir, { recursive: true });
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const frameworkStr = framework === "all" ? "all-frameworks" : framework;
  const filename = `audit-report-${frameworkStr}-${timestamp}.${format}`;
  const reportPath = path.join(baseDir, filename);

  const mappedControls = mapFindingsToControls(findings, framework);
  const controlsFailed = Object.values(mappedControls).filter(
    (c) => c.failed
  ).length;
  const controlsMapped = Object.keys(mappedControls).length;

  const summary = generateExecutiveSummary(
    findings,
    controlsMapped,
    controlsFailed
  );

  let content = "";
  if (format === "json") {
    content = generateJsonReport(
      findings,
      framework,
      mappedControls,
      organizationName,
      summary
    );
  } else if (format === "html") {
    content = generateHtmlReport(
      findings,
      framework,
      mappedControls,
      organizationName,
      summary
    );
  } else if (format === "csv") {
    content = generateCsvReport(
      findings,
      framework,
      mappedControls,
      organizationName
    );
  }

  fs.writeFileSync(reportPath, content, "utf-8");

  return {
    reportPath,
    framework,
    controlsMapped,
    controlsFailed,
    executiveSummary: summary,
  };
}

function mapFindingsToControls(
  findings: ScanFinding[],
  framework: string
): Record<string, { control: ControlMapping; failed: boolean }> {
  const mapped: Record<string, { control: ControlMapping; failed: boolean }> = {};

  // If no findings, return empty controls
  if (findings.length === 0) {
    return mapped;
  }

  const controls =
    framework === "soc2"
      ? SOC2_CONTROLS
      : framework === "iso27001"
        ? ISO27001_CONTROLS
        : framework === "nist-ai-rmf"
          ? NIST_AI_RMF_CONTROLS
          : { ...SOC2_CONTROLS, ...ISO27001_CONTROLS, ...NIST_AI_RMF_CONTROLS };

  Object.entries(controls).forEach(([id, control]) => {
    mapped[id] = {
      control,
      failed: findings.length > 0,
    };
  });

  return mapped;
}

function generateExecutiveSummary(
  findings: ScanFinding[],
  controlsMapped: number,
  controlsFailed: number
): string {
  const findingCount = findings.length;
  const criticalCount = findings.filter((f) => f.severity === "critical").length;

  return (
    `Audit Report Summary: ${findingCount} findings mapped to ${controlsMapped} controls. ` +
    `${controlsFailed} controls failed with ${criticalCount} critical findings. ` +
    `Risk level: ${criticalCount > 0 ? "High" : "Medium"}.`
  );
}

function generateJsonReport(
  findings: ScanFinding[],
  framework: string,
  mappedControls: Record<string, { control: ControlMapping; failed: boolean }>,
  organizationName: string | undefined,
  summary: string
): string {
  const report = {
    framework,
    organization: organizationName || "Unknown",
    generatedAt: new Date().toISOString(),
    summary,
    findings: findings.map((f) => ({
      category: f.category,
      technique: f.technique,
      severity: f.severity,
      description: f.description,
    })),
    controls: Object.entries(mappedControls).map(([id, { control, failed }]) => ({
      id,
      name: control.name,
      description: control.description,
      status: failed ? "failed" : "passed",
    })),
    statistics: {
      totalFindings: findings.length,
      criticalFindings: findings.filter((f) => f.severity === "critical").length,
      controlsMapped: Object.keys(mappedControls).length,
      controlsFailed: Object.values(mappedControls).filter((c) => c.failed).length,
    },
  };

  return JSON.stringify(report, null, 2);
}

function generateHtmlReport(
  findings: ScanFinding[],
  framework: string,
  mappedControls: Record<string, { control: ControlMapping; failed: boolean }>,
  organizationName: string | undefined,
  summary: string
): string {
  const controlsFailed = Object.values(mappedControls).filter(
    (c) => c.failed
  ).length;

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Audit Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
    .container { background: white; padding: 30px; border-radius: 8px; }
    h1 { color: #333; }
    .summary { background: #f0f0f0; padding: 15px; border-radius: 4px; margin: 20px 0; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th { background: #667eea; color: white; padding: 10px; text-align: left; }
    td { padding: 10px; border-bottom: 1px solid #ddd; }
    .critical { color: #d32f2f; font-weight: bold; }
    .high { color: #f57c00; }
    .medium { color: #fbc02d; }
    .low { color: #388e3c; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Audit Report</h1>
    ${organizationName ? `<p><strong>Organization:</strong> ${organizationName}</p>` : ""}
    <p><strong>Framework:</strong> ${framework}</p>
    <p><strong>Generated:</strong> ${new Date().toISOString()}</p>

    <div class="summary">
      <h2>Summary</h2>
      <p>${summary}</p>
    </div>

    <h2>Findings (${findings.length})</h2>
    ${
      findings.length > 0
        ? `
    <table>
      <tr>
        <th>Technique</th>
        <th>Category</th>
        <th>Severity</th>
        <th>Description</th>
      </tr>
      ${findings
        .map(
          (f) => `
      <tr>
        <td>${f.technique}</td>
        <td>${f.category}</td>
        <td class="${f.severity}">${f.severity}</td>
        <td>${f.description}</td>
      </tr>
      `
        )
        .join("")}
    </table>
    `
        : "<p>No findings</p>"
    }

    <h2>Controls (${controlsFailed} Failed)</h2>
    <table>
      <tr>
        <th>Control ID</th>
        <th>Name</th>
        <th>Status</th>
      </tr>
      ${Object.entries(mappedControls)
        .map(
          ([id, { control, failed }]) => `
      <tr>
        <td>${id}</td>
        <td>${control.name}</td>
        <td>${failed ? "Failed" : "Passed"}</td>
      </tr>
      `
        )
        .join("")}
    </table>
  </div>
</body>
</html>`;
}

function generateCsvReport(
  findings: ScanFinding[],
  framework: string,
  mappedControls: Record<string, { control: ControlMapping; failed: boolean }>,
  organizationName: string | undefined
): string {
  let csv = "Type,ID,Name,Details\n";

  csv += `Metadata,Framework,${framework},${organizationName || "Unknown"}\n`;
  csv += `Metadata,Generated,${new Date().toISOString()},\n\n`;

  csv += "Findings\n";
  csv +=
    "Technique,Category,Severity,Description\n" +
    findings
      .map(
        (f) =>
          `"${f.technique}","${f.category}","${f.severity}","${f.description}"`
      )
      .join("\n") +
    "\n\n";

  csv += "Controls\n";
  csv +=
    "Control ID,Name,Status\n" +
    Object.entries(mappedControls)
      .map(
        ([id, { control, failed }]) =>
          `"${id}","${control.name}","${failed ? "Failed" : "Passed"}"`
      )
      .join("\n") +
    "\n";

  return csv;
}
