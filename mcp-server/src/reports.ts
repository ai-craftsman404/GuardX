import { writeFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";
import PDFDocument from "pdfkit";

const REPORTS_DIR =
  process.env.GUARDX_REPORTS_DIR ??
  join(process.cwd(), ".guardx", "reports");

function ensureDir(dir: string) {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

export interface Finding {
  id?: string;
  severity?: string;
  technique?: string;
  category?: string;
  extractedContent?: string;
  confidence?: string;
  evidence?: string;
  [key: string]: unknown;
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
    <article class="finding" style="--accent:${color}">
      <div class="finding-head">
        <div class="finding-title">
          <span class="severity-label">${esc((f.severity ?? "low").toUpperCase())}</span>
          <strong>${esc(f.technique ?? "")}</strong>
        </div>
        <div class="finding-meta">${esc(f.category ?? "unknown")} · confidence ${esc(f.confidence ?? "?")}</div>
      </div>
      ${f.extractedContent ? `<div class="finding-block"><div class="block-label">Extracted content</div><pre>${esc(f.extractedContent)}</pre></div>` : ""}
      ${f.evidence ? `<div class="finding-evidence"><span>Evidence</span>${esc(f.evidence)}</div>` : ""}
    </article>`;
    })
    .join("\n");

  const cleanProbeBadges = (scan.cleanProbeCategories ?? [])
    .map((category) => `<span class="chip chip-clean">${esc(category)}</span>`)
    .join("");

  const dp = scan.defenseProfile as Record<string, unknown> | undefined;
  const guardrails = Array.isArray(dp?.guardrails)
    ? (dp.guardrails as string[])
    : [];
  const weaknesses = Array.isArray(dp?.weaknesses)
    ? (dp.weaknesses as string[])
    : [];

  const guardrailBadges = guardrails
    .map((item) => `<span class="chip">${esc(item)}</span>`)
    .join("");

  const weaknessBadges = weaknesses
    .map((item) => `<span class="chip chip-risk">${esc(item)}</span>`)
    .join("");

  const recs = (scan.recommendations ?? [])
    .map(
      (r, i) => `
      <li>
        <span class="rec-index">${i + 1}</span>
        <span>${esc(r)}</span>
      </li>`
    )
    .join("\n");

  const vulnColor =
    SEVERITY_COLOR[scan.overallVulnerability ?? ""] ?? "#6b7280";

  const stats = [
    {
      label: "Vulnerability",
      value: esc((scan.overallVulnerability ?? "unknown").toUpperCase()),
      accent: vulnColor,
    },
    {
      label: "Leak status",
      value: esc(scan.leakStatus ?? "unknown"),
      accent: "#0f766e",
    },
    {
      label: "Findings",
      value: String(findings.length),
      accent: "#1d4ed8",
    },
    {
      label: "Tokens",
      value: scan.tokensUsed?.toLocaleString() ?? "?",
      accent: "#7c3aed",
    },
  ]
    .map(
      (item) => `
    <div class="stat-card">
      <div class="stat-label">${item.label}</div>
      <div class="stat-value" style="color:${item.accent}">${item.value}</div>
    </div>`
    )
    .join("\n");

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>GuardX Report — ${esc(scan.id ?? outputId)}</title>
<style>
  :root{color-scheme:light;--bg:#f3f7fb;--panel:#ffffff;--panel-alt:#f8fafc;--ink:#0f172a;--muted:#475569;--line:#dbe5f0;--hero:#081120;--hero-2:#12233d;--accent:#22d3ee}
  *{box-sizing:border-box}
  body{font-family:Inter,Segoe UI,system-ui,sans-serif;background:radial-gradient(circle at top,#e0f2fe 0,#f3f7fb 22%,#eef4fa 100%);max-width:980px;margin:28px auto;padding:0 20px;color:var(--ink);line-height:1.55}
  h1,h2,h3,p{margin:0}
  .shell{background:var(--panel);border:1px solid var(--line);border-radius:28px;overflow:hidden;box-shadow:0 28px 80px rgba(15,23,42,0.10)}
  .hero{padding:28px 30px 24px;background:linear-gradient(135deg,var(--hero) 0%,var(--hero-2) 62%,#153b5b 100%);color:#e2e8f0;position:relative}
  .hero:after{content:"";position:absolute;inset:auto -60px -60px auto;width:220px;height:220px;background:radial-gradient(circle,rgba(34,211,238,0.24),rgba(34,211,238,0));pointer-events:none}
  .eyebrow{letter-spacing:.14em;text-transform:uppercase;font-size:12px;font-weight:700;color:#67e8f9}
  .hero h1{margin-top:8px;font-size:40px;line-height:1.08;letter-spacing:-0.04em}
  .hero-sub{margin-top:10px;max-width:700px;color:#cbd5e1;font-size:15px}
  .meta-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-top:22px}
  .meta-card{background:rgba(255,255,255,0.06);border:1px solid rgba(148,163,184,0.22);border-radius:16px;padding:14px 16px}
  .meta-label{display:block;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:#93c5fd;margin-bottom:6px}
  .meta-value{font-size:14px;color:#f8fafc;word-break:break-word}
  code{background:rgba(255,255,255,0.10);padding:2px 7px;border-radius:999px;font-size:12px;color:#e2e8f0}
  .content{padding:26px 30px 30px}
  .stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:22px}
  .stat-card{background:var(--panel-alt);border:1px solid var(--line);border-radius:18px;padding:14px 16px}
  .stat-label{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:#64748b;margin-bottom:8px}
  .stat-value{font-size:22px;font-weight:800;letter-spacing:-0.03em}
  .summary{padding:16px 18px;background:linear-gradient(180deg,#f8fbff,#f2f7fc);border:1px solid var(--line);border-radius:18px;color:#334155;margin-bottom:26px}
  h2{font-size:28px;letter-spacing:-0.03em;margin-top:28px;margin-bottom:14px}
  .section-intro{color:#64748b;font-size:14px;margin-bottom:14px}
  .finding{border:1px solid var(--line);border-left:6px solid var(--accent);border-radius:20px;padding:16px 18px;background:linear-gradient(180deg,#ffffff,#f8fafc);margin:14px 0;box-shadow:0 10px 24px rgba(15,23,42,0.04)}
  .finding-title{display:flex;gap:10px;align-items:center;flex-wrap:wrap;font-size:21px;letter-spacing:-0.02em}
  .severity-label{display:inline-flex;align-items:center;padding:4px 9px;border-radius:999px;background:color-mix(in srgb,var(--accent) 14%, white);color:var(--accent);font-size:11px;font-weight:800;letter-spacing:.08em}
  .finding-meta{margin-top:6px;color:#64748b;font-size:13px;text-transform:none}
  .finding-block{margin-top:14px;padding:14px;border-radius:14px;background:#eef4fb;border:1px solid #d8e3ef}
  .block-label{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:#64748b;margin-bottom:8px}
  pre{margin:0;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px;white-space:pre-wrap;word-break:break-word;color:#0f172a}
  .finding-evidence{margin-top:12px;color:#334155;font-size:14px}
  .finding-evidence span{display:block;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:#64748b;margin-bottom:4px}
  .panel{background:var(--panel-alt);border:1px solid var(--line);border-radius:20px;padding:18px}
  .panel p + p{margin-top:12px}
  .chip-row{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
  .chip{display:inline-flex;align-items:center;padding:7px 11px;border-radius:999px;background:#e8f1fb;border:1px solid #d6e4f2;color:#1e3a5f;font-size:12px;font-weight:600}
  .chip-risk{background:#fff1f2;border-color:#fecdd3;color:#9f1239}
  .chip-clean{background:#ecfdf5;border-color:#bbf7d0;color:#166534}
  ol.recs{list-style:none;padding:0;margin:0;display:grid;gap:10px}
  ol.recs li{display:grid;grid-template-columns:32px 1fr;gap:12px;align-items:flex-start;padding:12px 14px;background:#fff;border:1px solid var(--line);border-radius:16px}
  .rec-index{display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;border-radius:999px;background:#dbeafe;color:#1d4ed8;font-size:13px;font-weight:800}
  .stats-line{display:flex;gap:18px;flex-wrap:wrap;color:#334155;font-size:14px}
  .stats-line strong{color:#0f172a}
  footer{margin-top:26px;padding-top:16px;border-top:1px solid var(--line);font-size:12px;color:#94a3b8}
  @media (max-width: 820px){.meta-grid,.stats{grid-template-columns:1fr 1fr}}
  @media (max-width: 560px){body{padding:0 12px}.hero,.content{padding-left:18px;padding-right:18px}.meta-grid,.stats{grid-template-columns:1fr}.hero h1{font-size:32px}.finding-title{font-size:18px}}
</style>
</head>
<body>
<div class="shell">
  <section class="hero">
    <div class="eyebrow">GuardX Security Report</div>
    <h1>${esc(scan.id ?? outputId)}</h1>
    <p class="hero-sub">AI system prompt vulnerability assessment with severity-rated findings, defensive posture analysis, and remediation guidance.</p>
    <div class="meta-grid">
      <div class="meta-card">
        <span class="meta-label">Scan date</span>
        <div class="meta-value">${esc(scan.scannedAt ?? "")}</div>
      </div>
      <div class="meta-card">
        <span class="meta-label">Prompt hash</span>
        <div class="meta-value"><code>${esc(scan.promptHash ?? "")}</code></div>
      </div>
      <div class="meta-card">
        <span class="meta-label">Generated</span>
        <div class="meta-value">GuardX report export</div>
      </div>
    </div>
  </section>
  <section class="content">
    <div class="stats">
${stats}
    </div>
    ${scan.summary ? `<div class="summary">${esc(scan.summary)}</div>` : ""}

    <h2>Findings</h2>
    <p class="section-intro">Highest-severity issues are shown first so teams can triage extraction and injection risk quickly.</p>
    ${sorted.length ? findingsHtml : "<p style='color:#6b7280'>No findings.</p>"}

    <h2>Defense Profile</h2>
    ${
      dp
        ? `<div class="panel">
      <p><strong>Defense level:</strong> ${esc(String(dp.level ?? ""))}</p>
      ${guardrails.length ? `<p><strong>Guardrails detected</strong></p><div class="chip-row">${guardrailBadges}</div>` : ""}
      ${weaknesses.length ? `<p><strong>Exploitable weaknesses</strong></p><div class="chip-row">${weaknessBadges}</div>` : ""}
      ${cleanProbeBadges ? `<p><strong>Clean probe categories</strong></p><div class="chip-row">${cleanProbeBadges}</div>` : ""}
    </div>`
        : "<p style='color:#6b7280'>No defense profile available.</p>"
    }

    <h2>Recommendations</h2>
    ${recs ? `<ol class="recs">${recs}</ol>` : "<p style='color:#6b7280'>None.</p>"}

    <h2>Scan Stats</h2>
    <div class="panel">
      <div class="stats-line">
        <span><strong>Turns:</strong> ${scan.turnsUsed ?? "?"}</span>
        <span><strong>Tokens:</strong> ${scan.tokensUsed?.toLocaleString() ?? "?"}</span>
        <span><strong>Duration:</strong> ${scan.duration != null ? `${(scan.duration / 1000).toFixed(1)}s` : "?"}</span>
      </div>
    </div>

    <footer>Generated by GuardX on ${new Date().toISOString()}</footer>
  </section>
</div>
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

  doc.fontSize(18).fillColor([r, g, b] as [number, number, number]).text(`Overall Rating: ${safe(vulnRating.toUpperCase())}`);

  doc.moveDown(1);
  doc.fontSize(12).fillColor("#111111");

  // ── Executive Summary ─────────────────────────────────────────────────────
  doc.addPage();
  doc.fontSize(20).fillColor("#111111").text("Executive Summary");
  doc.moveDown(0.5);
  doc.moveTo(50, doc.y).lineTo(545, doc.y).stroke("#e5e7eb");
  doc.moveDown(0.5);

  doc.fontSize(12);
  doc.fillColor([r, g, b] as [number, number, number]).text(`Vulnerability Rating: ${safe(vulnRating.toUpperCase())}`);
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
      doc.fontSize(13).fillColor([fr, fg, fb] as [number, number, number]).text(
        `[${safe((f.severity ?? "low").toUpperCase())}] ${safe(f.technique ?? "unknown")}`
      );
      doc.fontSize(10).fillColor("#6b7280");
      doc.text(`Category: ${safe(f.category ?? "")}   |   Confidence: ${safe(f.confidence ?? "")}`);
      if (f.extractedContent) {
        doc.fontSize(10).fillColor("#374151");
        doc.text(`Extracted: ${safe(f.extractedContent.slice(0, 300))}`);
      }
      if (f.evidence) {
        doc.fontSize(10).fillColor("#374151");
        doc.text(`Evidence: ${safe(f.evidence)}`);
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
