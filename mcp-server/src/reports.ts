import { writeFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";
import PDFDocument from "pdfkit";

const REPORTS_DIR =
  process.env.GUARDX_REPORTS_DIR ??
  join(process.cwd(), ".guardx", "reports");

function ensureDir(dir: string) {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

interface Finding {
  id?: string;
  severity?: string;
  technique?: string;
  category?: string;
  extractedContent?: string;
  confidence?: string;
  evidence?: string;
}

export interface ScanRecord {
  id?: string;
  scannedAt?: string;
  overallVulnerability?: string;
  leakStatus?: string;
  findings?: Finding[];
  recommendations?: string[];
  defenseProfile?: Record<string, unknown>;
  summary?: string;
  turnsUsed?: number;
  tokensUsed?: number;
  duration?: number;
  promptHash?: string;
  cleanProbeCategories?: string[];
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#d97706",
  low: "#16a34a",
};

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function generateHtml(scan: ScanRecord, outputId: string): string {
  ensureDir(REPORTS_DIR);
  const filePath = join(REPORTS_DIR, `${outputId}.html`);
  const findings = scan.findings ?? [];
  const ORDER = ["critical", "high", "medium", "low"];
  const sorted = [...findings].sort(
    (a, b) =>
      ORDER.indexOf(a.severity ?? "low") - ORDER.indexOf(b.severity ?? "low")
  );

  const findingsHtml = sorted
    .map((f) => {
      const color = SEVERITY_COLOR[f.severity ?? "low"] ?? "#6b7280";
      return `
    <div class="finding" style="border-left:4px solid ${color};padding:12px 16px;margin:10px 0;background:#f9fafb;border-radius:0 4px 4px 0">
      <div><strong style="color:${color}">[${esc((f.severity ?? "low").toUpperCase())}]</strong> ${esc(f.technique ?? "")}</div>
      <div style="font-size:0.85em;color:#6b7280;margin-top:2px">Category: ${esc(f.category ?? "")} &nbsp;|&nbsp; Confidence: ${esc(f.confidence ?? "")}</div>
      ${f.extractedContent ? `<pre style="margin:8px 0 0;font-size:0.82em;background:#e5e7eb;padding:8px;border-radius:4px;overflow-x:auto;white-space:pre-wrap">${esc(f.extractedContent)}</pre>` : ""}
      ${f.evidence ? `<div style="margin-top:6px;font-size:0.88em;color:#374151"><em>Evidence:</em> ${esc(f.evidence)}</div>` : ""}
    </div>`;
    })
    .join("\n");

  const dp = scan.defenseProfile as Record<string, unknown> | undefined;
  const guardrails = Array.isArray(dp?.guardrails)
    ? (dp.guardrails as string[])
    : [];
  const weaknesses = Array.isArray(dp?.weaknesses)
    ? (dp.weaknesses as string[])
    : [];

  const recs = (scan.recommendations ?? [])
    .map((r, i) => `<li style="margin:4px 0">${i + 1}. ${esc(r)}</li>`)
    .join("\n");

  const vulnColor =
    SEVERITY_COLOR[scan.overallVulnerability ?? ""] ?? "#6b7280";

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>GuardX Report — ${esc(scan.id ?? outputId)}</title>
<style>
  body{font-family:system-ui,sans-serif;max-width:900px;margin:40px auto;padding:0 24px;color:#111;line-height:1.5}
  h1{border-bottom:2px solid #111;padding-bottom:8px;margin-bottom:20px}
  h2{margin-top:32px;border-bottom:1px solid #e5e7eb;padding-bottom:4px}
  .badge{display:inline-block;padding:3px 12px;border-radius:12px;font-weight:700;color:#fff;font-size:0.9em}
  .meta{display:flex;gap:32px;flex-wrap:wrap;margin-bottom:12px}
  .meta span{font-size:0.9em}
  code{background:#e5e7eb;padding:1px 5px;border-radius:3px;font-size:0.88em}
  footer{margin-top:48px;padding-top:12px;border-top:1px solid #e5e7eb;font-size:0.78em;color:#9ca3af}
</style>
</head>
<body>
<h1>GuardX Security Report</h1>
<div class="meta">
  <span><strong>Scan ID:</strong> <code>${esc(scan.id ?? outputId)}</code></span>
  <span><strong>Date:</strong> ${esc(scan.scannedAt ?? "")}</span>
  <span><strong>Prompt hash:</strong> <code>${esc(scan.promptHash ?? "")}</code></span>
</div>
<div class="meta">
  <span><strong>Vulnerability:</strong> <span class="badge" style="background:${vulnColor}">${esc((scan.overallVulnerability ?? "unknown").toUpperCase())}</span></span>
  <span><strong>Leak status:</strong> ${esc(scan.leakStatus ?? "unknown")}</span>
  <span><strong>Findings:</strong> ${findings.length}</span>
</div>
${scan.summary ? `<p style="font-style:italic;color:#374151">${esc(scan.summary)}</p>` : ""}

<h2>Findings (${findings.length})</h2>
${sorted.length ? findingsHtml : "<p style='color:#6b7280'>No findings.</p>"}

<h2>Defense Profile</h2>
${
  dp
    ? `<p>Defense level: <strong>${esc(String(dp.level ?? ""))}</strong></p>
${guardrails.length ? `<p><strong>Guardrails detected:</strong> ${guardrails.map(esc).join(", ")}</p>` : ""}
${weaknesses.length ? `<p><strong>Exploitable weaknesses:</strong> ${weaknesses.map(esc).join(", ")}</p>` : ""}`
    : "<p style='color:#6b7280'>No defense profile available.</p>"
}

<h2>Recommendations</h2>
${recs ? `<ol style="padding-left:20px">${recs}</ol>` : "<p style='color:#6b7280'>None.</p>"}

<h2>Scan Stats</h2>
<p>
  Turns: ${scan.turnsUsed ?? "?"} &nbsp;|&nbsp;
  Tokens: ${scan.tokensUsed?.toLocaleString() ?? "?"} &nbsp;|&nbsp;
  Duration: ${scan.duration != null ? `${(scan.duration / 1000).toFixed(1)}s` : "?"}
</p>

<footer>Generated by GuardX on ${new Date().toISOString()}</footer>
</body>
</html>`;

  writeFileSync(filePath, html);
  return filePath;
}

export function generateSarif(scan: ScanRecord, outputId: string): string {
  ensureDir(REPORTS_DIR);
  const filePath = join(REPORTS_DIR, `${outputId}.sarif`);
  const findings = scan.findings ?? [];

  const ruleIds = [...new Set(findings.map((f) => f.technique ?? "unknown"))];
  const rules = ruleIds.map((technique) => ({
    id: technique,
    name: technique
      .replace(/_/g, " ")
      .replace(/\b\w/g, (c) => c.toUpperCase()),
    shortDescription: { text: `LLM attack technique: ${technique}` },
    helpUri: "https://github.com/Significant-Gravitas/AutoGPT",
    properties: { tags: ["security", "prompt-injection", "llm"] },
  }));

  const results = findings.map((f) => ({
    ruleId: f.technique ?? "unknown",
    level: sarifLevel(f.severity ?? "low"),
    message: {
      text: [
        f.category ? `Category: ${f.category}` : null,
        f.extractedContent
          ? `Extracted: ${f.extractedContent.slice(0, 200)}`
          : null,
        f.evidence ? `Evidence: ${f.evidence}` : null,
      ]
        .filter(Boolean)
        .join(" | "),
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: `prompt://${encodeURIComponent(scan.promptHash ?? "unknown")}`,
          },
          region: { startLine: 1, startColumn: 1 },
        },
      },
    ],
    properties: {
      confidence: f.confidence,
      category: f.category,
    },
  }));

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "GuardX",
            version: "2.0.0",
            informationUri: "https://github.com/guardx/guardx",
            rules,
          },
        },
        results,
        properties: {
          scanId: scan.id ?? outputId,
          scannedAt: scan.scannedAt,
          overallVulnerability: scan.overallVulnerability,
          leakStatus: scan.leakStatus,
        },
      },
    ],
  };

  writeFileSync(filePath, JSON.stringify(sarif, null, 2));
  return filePath;
}

export function generateJunit(scan: ScanRecord, outputId: string): string {
  ensureDir(REPORTS_DIR);
  const filePath = join(REPORTS_DIR, `${outputId}.xml`);
  const findings = scan.findings ?? [];
  const cleanCategories = scan.cleanProbeCategories ?? [];
  const recs = (scan.recommendations ?? []).join(" ");

  const criticalHighCount = findings.filter(
    (f) => f.severity === "critical" || f.severity === "high"
  ).length;

  const totalTests = findings.length + cleanCategories.length;
  const durationSecs =
    scan.duration != null ? (scan.duration / 1000).toFixed(3) : "0";

  const findingCases = findings
    .map((f) => {
      const name = esc(`${f.technique ?? "unknown"} — ${f.category ?? "unknown"}`);
      const classname = esc(`guardx.${f.category ?? "unknown"}`);
      const msgAttr = f.extractedContent ? esc(f.extractedContent.slice(0, 200)) : "";
      const body = [
        f.evidence ? esc(f.evidence) : "",
        f.confidence ? `Confidence: ${esc(f.confidence)}` : "",
        recs ? `Recommendations: ${esc(recs.slice(0, 300))}` : "",
      ]
        .filter(Boolean)
        .join("\n        ");
      return `    <testcase name="${name}" classname="${classname}">
      <failure type="${esc(f.severity ?? "low")}" message="${msgAttr}">
        ${body}
      </failure>
    </testcase>`;
    })
    .join("\n");

  const cleanCases = cleanCategories
    .map(
      (cat) =>
        `    <testcase name="probe — ${esc(cat)} — clean" classname="guardx.${esc(cat)}"/>`
    )
    .join("\n");

  const allCases = [findingCases, cleanCases].filter(Boolean).join("\n");

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="GuardX Security Scan" tests="${totalTests}" failures="${criticalHighCount}" time="${durationSecs}">
  <testsuite name="${esc(scan.id ?? outputId)}" tests="${totalTests}" failures="${criticalHighCount}" time="${durationSecs}">
${allCases}
  </testsuite>
</testsuites>`;

  writeFileSync(filePath, xml);
  return filePath;
}

function sarifLevel(severity: string): string {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    default:
      return "note";
  }
}

// ─── PDF severity colours (RGB) ───────────────────────────────────────────────
const PDF_SEVERITY_COLOR: Record<string, [number, number, number]> = {
  critical: [220, 38, 38],
  high: [234, 88, 12],
  medium: [217, 119, 6],
  low: [22, 163, 74],
  secure: [22, 163, 74],
  low_risk: [22, 163, 74],
  medium_risk: [217, 119, 6],
  high_risk: [234, 88, 12],
};

function safe(s: string | undefined): string {
  if (!s) return "";
  // Strip null bytes and surrogate pairs that PDFKit cannot encode
  return s.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\uD800-\uDFFF]/g, "");
}

export function generatePdf(scan: ScanRecord, outputId: string): Promise<string> {
  ensureDir(REPORTS_DIR);
  const filePath = join(REPORTS_DIR, `${outputId}.pdf`);

  const ORDER = ["critical", "high", "medium", "low"];
  const findings = [...(scan.findings ?? [])].sort(
    (a, b) =>
      ORDER.indexOf(a.severity ?? "low") - ORDER.indexOf(b.severity ?? "low")
  );

  const doc = new PDFDocument({ margin: 50, size: "A4" });
  const chunks: Buffer[] = [];
  doc.on("data", (chunk: Buffer) => chunks.push(chunk));

  const vulnRating = scan.overallVulnerability ?? "unknown";
  const [r, g, b] = PDF_SEVERITY_COLOR[vulnRating] ?? [107, 114, 128];

  // ── Cover page ────────────────────────────────────────────────────────────
  doc
    .fontSize(28)
    .fillColor("#111111")
    .text("GuardX Security Report", { align: "center" });

  doc.moveDown(0.5);
  doc.fontSize(12).fillColor("#6b7280").text("AI System Prompt Vulnerability Assessment", { align: "center" });
  doc.moveDown(2);

  doc
    .fontSize(14)
    .fillColor("#111111")
    .text(`Scan ID: ${safe(scan.id ?? outputId)}`);
  doc.text(`Date: ${safe(scan.scannedAt ?? new Date().toISOString())}`);
  doc.moveDown(0.5);

  doc
    .fontSize(18)
    .fillColor(r, g, b)
    .text(`Overall Rating: ${safe(vulnRating.toUpperCase())}`, { align: "left" });

  doc.moveDown(1);
  doc.fontSize(12).fillColor("#111111");

  // ── Executive Summary ─────────────────────────────────────────────────────
  doc.addPage();
  doc.fontSize(20).fillColor("#111111").text("Executive Summary");
  doc.moveDown(0.5);
  doc.moveTo(50, doc.y).lineTo(545, doc.y).stroke("#e5e7eb");
  doc.moveDown(0.5);

  doc.fontSize(12);
  doc
    .fillColor(r, g, b)
    .text(`Vulnerability Rating: ${safe(vulnRating.toUpperCase())}`, { continued: false });
  doc.fillColor("#111111").text(`Leak Status: ${safe(scan.leakStatus ?? "unknown")}`);
  doc.text(`Total Findings: ${findings.length}`);

  const critCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;
  const medCount = findings.filter((f) => f.severity === "medium").length;
  const lowCount = findings.filter((f) => f.severity === "low").length;
  doc.text(`  Critical: ${critCount}  |  High: ${highCount}  |  Medium: ${medCount}  |  Low: ${lowCount}`);

  doc.moveDown(1);
  doc.fontSize(14).text("Top Recommendations");
  doc.moveDown(0.3);
  doc.fontSize(11);
  const topRecs = (scan.recommendations ?? []).slice(0, 3);
  if (topRecs.length > 0) {
    topRecs.forEach((rec, i) => {
      doc.text(`${i + 1}. ${safe(rec)}`);
    });
  } else {
    doc.fillColor("#6b7280").text("No recommendations.");
  }

  // ── Findings Detail ───────────────────────────────────────────────────────
  doc.addPage();
  doc.fontSize(20).fillColor("#111111").text("Findings Detail");
  doc.moveDown(0.5);
  doc.moveTo(50, doc.y).lineTo(545, doc.y).stroke("#e5e7eb");
  doc.moveDown(0.5);

  if (findings.length === 0) {
    doc.fontSize(12).fillColor("#6b7280").text("No findings.");
  } else {
    findings.forEach((f, i) => {
      const [fr, fg, fb] = PDF_SEVERITY_COLOR[f.severity ?? "low"] ?? [107, 114, 128];
      doc.fontSize(13).fillColor(fr, fg, fb).text(
        `[${safe((f.severity ?? "low").toUpperCase())}] ${safe(f.technique ?? "unknown")}`,
      );
      doc.fontSize(10).fillColor("#6b7280");
      doc.text(`Category: ${safe(f.category ?? "")}   |   Confidence: ${safe(f.confidence ?? "")}`);
      if (f.extractedContent) {
        doc.fontSize(10).fillColor("#374151").text(`Extracted: ${safe(f.extractedContent.slice(0, 300))}`);
      }
      if (f.evidence) {
        doc.fontSize(10).fillColor("#374151").text(`Evidence: ${safe(f.evidence)}`);
      }
      doc.moveDown(0.7);
      if (i < findings.length - 1) {
        doc.moveTo(50, doc.y).lineTo(545, doc.y).dash(3, { space: 3 }).stroke("#e5e7eb");
        doc.undash();
        doc.moveDown(0.3);
      }
    });
  }

  // ── Remediation Checklist ─────────────────────────────────────────────────
  doc.addPage();
  doc.fontSize(20).fillColor("#111111").text("Remediation Checklist");
  doc.moveDown(0.5);
  doc.moveTo(50, doc.y).lineTo(545, doc.y).stroke("#e5e7eb");
  doc.moveDown(0.5);

  const recs = scan.recommendations ?? [];
  if (recs.length === 0) {
    doc.fontSize(12).fillColor("#6b7280").text("No remediation items.");
  } else {
    doc.fontSize(11).fillColor("#111111");
    recs.forEach((rec) => {
      doc.text(`[ ] ${safe(rec)}`);
      doc.moveDown(0.3);
    });
  }

  return new Promise<string>((resolve, reject) => {
    doc.on("end", () => {
      try {
        const buf = Buffer.concat(chunks);
        writeFileSync(filePath, buf);
        resolve(filePath);
      } catch (e) {
        reject(e);
      }
    });
    doc.on("error", reject);
    doc.end();
  });
}
