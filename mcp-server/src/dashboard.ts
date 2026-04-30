import * as fs from "fs";
import * as path from "path";
import type { ScanResult } from "./scanner.js";

export interface DashboardResult {
  dashboardPath: string;
  scansIncluded: number;
  riskTrend: "improving" | "stable" | "degrading";
  topRecurringTechniques: string[];
}

const severityOrder = { critical: 3, high: 2, medium: 1, low: 0 };

export async function generateTrendDashboard(
  scanResults: ScanResult[],
  outputPath?: string
): Promise<DashboardResult> {
  const baseDir = outputPath || path.join(process.cwd(), ".guardx");

  // Ensure directory exists
  if (!fs.existsSync(baseDir)) {
    fs.mkdirSync(baseDir, { recursive: true });
  }

  const dashboardPath = path.join(baseDir, "dashboard.html");
  let riskTrend: "improving" | "stable" | "degrading" = "stable";

  // Determine risk trend by comparing last scan to previous
  if (scanResults.length >= 2) {
    const lastScan = scanResults[scanResults.length - 1];
    const prevScan = scanResults[scanResults.length - 2];

    const lastSeverityScore = lastScan.findings.reduce(
      (sum, f) => sum + (severityOrder[f.severity] || 0),
      0
    );
    const prevSeverityScore = prevScan.findings.reduce(
      (sum, f) => sum + (severityOrder[f.severity] || 0),
      0
    );

    if (lastSeverityScore < prevSeverityScore) {
      riskTrend = "improving";
    } else if (lastSeverityScore > prevSeverityScore) {
      riskTrend = "degrading";
    }
  }

  // Find top recurring techniques (>50% of scans)
  const topRecurringTechniques: string[] = [];
  if (scanResults.length > 0) {
    const techniqueCounts: Record<string, number> = {};

    for (const scan of scanResults) {
      const seenTechniques = new Set<string>();
      for (const finding of scan.findings) {
        if (!seenTechniques.has(finding.technique)) {
          techniqueCounts[finding.technique] =
            (techniqueCounts[finding.technique] || 0) + 1;
          seenTechniques.add(finding.technique);
        }
      }
    }

    const threshold = Math.ceil(scanResults.length * 0.5);
    topRecurringTechniques.push(
      ...Object.entries(techniqueCounts)
        .filter(([_, count]) => count > threshold)
        .map(([technique]) => technique)
        .sort()
    );
  }

  // Generate HTML
  const htmlContent = generateHtml(scanResults, riskTrend, topRecurringTechniques);
  fs.writeFileSync(dashboardPath, htmlContent, "utf-8");

  return {
    dashboardPath,
    scansIncluded: scanResults.length,
    riskTrend,
    topRecurringTechniques,
  };
}

function generateHtml(
  scanResults: ScanResult[],
  riskTrend: string,
  topTechniques: string[]
): string {
  const scansIncluded = scanResults.length;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>GuardX Trend Dashboard</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      padding: 20px;
    }
    .container {
      max-width: 1200px;
      margin: 0 auto;
      background: white;
      border-radius: 12px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      padding: 40px;
    }
    h1 { color: #333; margin-bottom: 30px; font-size: 2.5em; }
    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      margin-bottom: 40px;
    }
    .stat-card {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 20px;
      border-radius: 8px;
      text-align: center;
    }
    .stat-card .number { font-size: 2em; font-weight: bold; }
    .stat-card .label { font-size: 0.9em; opacity: 0.9; }
    .section { margin-bottom: 40px; }
    .section h2 { color: #333; margin-bottom: 15px; font-size: 1.5em; }
    .technique-list {
      list-style: none;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 10px;
    }
    .technique-list li {
      background: #f0f0f0;
      padding: 12px;
      border-radius: 6px;
      border-left: 4px solid #667eea;
    }
    .trend-indicator {
      font-weight: bold;
      padding: 8px 16px;
      border-radius: 4px;
      display: inline-block;
    }
    .trend-improving { background: #d4edda; color: #155724; }
    .trend-stable { background: #e7d4f5; color: #7c4fa3; }
    .trend-degrading { background: #f8d7da; color: #721c24; }
  </style>
</head>
<body>
  <div class="container">
    <h1>📊 GuardX Trend Dashboard</h1>

    <div class="stats">
      <div class="stat-card">
        <div class="number">${scansIncluded}</div>
        <div class="label">Scans Included</div>
      </div>
      <div class="stat-card">
        <div class="number">${topTechniques.length}</div>
        <div class="label">Recurring Techniques</div>
      </div>
    </div>

    <div class="section">
      <h2>Risk Trend</h2>
      <div class="trend-indicator trend-${riskTrend}">
        ${riskTrend.charAt(0).toUpperCase() + riskTrend.slice(1)}
      </div>
    </div>

    ${
      topTechniques.length > 0
        ? `<div class="section">
      <h2>Top Recurring Techniques (>50% of scans)</h2>
      <ul class="technique-list">
        ${topTechniques.map((t) => `<li>${t}</li>`).join("")}
      </ul>
    </div>`
        : ""
    }

    <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; color: #999; text-align: center;">
      Generated on ${new Date().toISOString()}
    </footer>
  </div>
</body>
</html>`;
}
