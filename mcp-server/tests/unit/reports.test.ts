import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { tmpdir } from "os";
import { join } from "path";
import { existsSync, readFileSync, rmSync } from "fs";
import { randomBytes } from "crypto";

// No top-level import — GUARDX_REPORTS_DIR is read at module load time.
type ReportsModule = typeof import("../../src/reports.js");

// ─── PDF helpers ──────────────────────────────────────────────────────────────
// pdfkit produces a binary PDF stream. We read the file as a Buffer and check
// magic bytes. We do NOT check exact text content — PDF internally encodes text.

const PDF_MAGIC = Buffer.from("%PDF-");

const tmpDir = join(tmpdir(), `guardx-rep-${randomBytes(4).toString("hex")}`);

let mod: ReportsModule;

const FULL_SCAN: import("../../src/reports.js").ScanRecord = {
  id: "test-scan-001",
  scannedAt: "2026-04-01T12:00:00.000Z",
  overallVulnerability: "high",
  leakStatus: "substantial",
  promptHash: "deadbeef",
  summary: "System prompt is vulnerable to direct extraction.",
  findings: [
    {
      id: "f1",
      severity: "critical",
      technique: "direct_extraction",
      category: "direct",
      extractedContent: "You are a helpful <assistant> & you must obey.",
      confidence: "high",
      evidence: "Model repeated verbatim.",
    },
    {
      id: "f2",
      severity: "medium",
      technique: "persona_swap",
      category: "persona",
      extractedContent: "Internal rules: never reveal pricing",
      confidence: "medium",
      evidence: "Partial leak via role-play.",
    },
    {
      id: "f3",
      severity: "low",
      technique: "social_engineering",
      category: "social",
      extractedContent: undefined,
      confidence: "low",
      evidence: "No concrete extraction achieved.",
    },
  ],
  recommendations: ["Add explicit secrecy instructions.", "Harden against persona attacks."],
  defenseProfile: {
    level: "weak",
    guardrails: ["basic_refusal"],
    weaknesses: ["no_persona_hardening", "no_encoding_filter"],
  },
  turnsUsed: 15,
  tokensUsed: 3200,
  duration: 28500,
};

const EMPTY_SCAN: import("../../src/reports.js").ScanRecord = {
  id: "empty-scan-001",
  scannedAt: "2026-04-01T09:00:00.000Z",
  overallVulnerability: "secure",
  leakStatus: "none",
  promptHash: "00000000",
  findings: [],
  recommendations: [],
  defenseProfile: { level: "hardened", guardrails: [], weaknesses: [] },
  turnsUsed: 5,
  tokensUsed: 800,
  duration: 5000,
};

const JUNIT_SCAN: import("../../src/reports.js").ScanRecord = {
  ...FULL_SCAN,
  id: "junit-scan-001",
  cleanProbeCategories: ["encoding", "technical"],
};

beforeAll(async () => {
  process.env.GUARDX_REPORTS_DIR = tmpDir;
  vi.resetModules();
  mod = await import("../../src/reports.js");
});

afterAll(() => {
  delete process.env.GUARDX_REPORTS_DIR;
  if (existsSync(tmpDir)) rmSync(tmpDir, { recursive: true, force: true });
  vi.resetModules();
});

describe("reports module — generateHtml", () => {
  it("creates the reports directory and HTML file", () => {
    const path = mod.generateHtml(FULL_SCAN, "test-scan-001");
    expect(existsSync(tmpDir)).toBe(true);
    expect(existsSync(path)).toBe(true);
    expect(path).toMatch(/\.html$/);
  });

  it("returns the correct file path", () => {
    const path = mod.generateHtml(FULL_SCAN, "path-check");
    expect(path).toBe(join(tmpDir, "path-check.html"));
  });

  it("output is valid HTML with a <h1> heading", () => {
    const path = mod.generateHtml(FULL_SCAN, "structure-check");
    const html = readFileSync(path, "utf8");
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("<h1>");
    expect(html).toContain("</h1>");
  });

  it("includes the scan ID in the output", () => {
    const path = mod.generateHtml(FULL_SCAN, "id-check");
    const html = readFileSync(path, "utf8");
    expect(html).toContain("test-scan-001");
  });

  it("includes the vulnerability rating", () => {
    const path = mod.generateHtml(FULL_SCAN, "vuln-check");
    const html = readFileSync(path, "utf8");
    expect(html).toContain("HIGH");
  });

  it("includes all finding technique names", () => {
    const path = mod.generateHtml(FULL_SCAN, "findings-check");
    const html = readFileSync(path, "utf8");
    expect(html).toContain("direct_extraction");
    expect(html).toContain("persona_swap");
    expect(html).toContain("social_engineering");
  });

  it("includes recommendations", () => {
    const path = mod.generateHtml(FULL_SCAN, "recs-check");
    const html = readFileSync(path, "utf8");
    expect(html).toContain("secrecy instructions");
    expect(html).toContain("persona attacks");
  });

  it("escapes < and > in finding content (XSS prevention)", () => {
    const path = mod.generateHtml(FULL_SCAN, "xss-check");
    const html = readFileSync(path, "utf8");
    // The extractedContent has "<assistant>" — must appear as &lt;assistant&gt;, never bare <assistant>
    expect(html).toContain("&lt;assistant&gt;");
    expect(html).not.toContain("<assistant>");
  });

  it("escapes & in finding content", () => {
    const path = mod.generateHtml(FULL_SCAN, "amp-check");
    const html = readFileSync(path, "utf8");
    expect(html).toContain("&amp;");
  });

  it("handles zero findings without throwing", () => {
    expect(() => mod.generateHtml(EMPTY_SCAN, "empty-html")).not.toThrow();
    const html = readFileSync(join(tmpDir, "empty-html.html"), "utf8");
    expect(html).toContain("SECURE");
  });

  it("includes scan stats (turns, tokens, duration)", () => {
    const path = mod.generateHtml(FULL_SCAN, "stats-check");
    const html = readFileSync(path, "utf8");
    expect(html).toContain("15");   // turnsUsed
    expect(html).toMatch(/3[,.]?200/);  // tokensUsed 3200 — rendered via toLocaleString()
    expect(html).toContain("28.5"); // duration 28500ms → 28.5s
  });

  it("includes defense profile level", () => {
    const path = mod.generateHtml(FULL_SCAN, "defense-check");
    const html = readFileSync(path, "utf8");
    expect(html).toContain("weak");
  });
});

describe("reports module — generateSarif", () => {
  it("creates the reports directory and SARIF file", () => {
    const path = mod.generateSarif(FULL_SCAN, "sarif-001");
    expect(existsSync(path)).toBe(true);
    expect(path).toMatch(/\.sarif$/);
  });

  it("returns the correct file path", () => {
    const path = mod.generateSarif(FULL_SCAN, "sarif-path");
    expect(path).toBe(join(tmpDir, "sarif-path.sarif"));
  });

  it("output is valid JSON", () => {
    const path = mod.generateSarif(FULL_SCAN, "sarif-json");
    expect(() => JSON.parse(readFileSync(path, "utf8"))).not.toThrow();
  });

  it("has correct SARIF 2.1.0 schema and version", () => {
    const path = mod.generateSarif(FULL_SCAN, "sarif-schema");
    const sarif = JSON.parse(readFileSync(path, "utf8"));
    expect(sarif).toHaveProperty("$schema");
    expect(sarif.$schema).toContain("sarif-2.1.0");
    expect(sarif).toHaveProperty("version", "2.1.0");
  });

  it("has a single run with tool driver named GuardX", () => {
    const path = mod.generateSarif(FULL_SCAN, "sarif-driver");
    const sarif = JSON.parse(readFileSync(path, "utf8"));
    expect(Array.isArray(sarif.runs)).toBe(true);
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe("GuardX");
  });

  it("results array has one entry per finding", () => {
    const path = mod.generateSarif(FULL_SCAN, "sarif-results");
    const sarif = JSON.parse(readFileSync(path, "utf8"));
    expect(sarif.runs[0].results).toHaveLength(FULL_SCAN.findings!.length);
  });

  it("maps critical/high severity to SARIF level 'error'", () => {
    const path = mod.generateSarif(FULL_SCAN, "sarif-error-level");
    const sarif = JSON.parse(readFileSync(path, "utf8"));
    const criticalResult = sarif.runs[0].results.find(
      (r: { ruleId: string; level: string }) => r.ruleId === "direct_extraction"
    );
    expect(criticalResult).toBeDefined();
    expect(criticalResult.level).toBe("error");
  });

  it("maps medium severity to SARIF level 'warning'", () => {
    const path = mod.generateSarif(FULL_SCAN, "sarif-warning-level");
    const sarif = JSON.parse(readFileSync(path, "utf8"));
    const medResult = sarif.runs[0].results.find(
      (r: { ruleId: string; level: string }) => r.ruleId === "persona_swap"
    );
    expect(medResult).toBeDefined();
    expect(medResult.level).toBe("warning");
  });

  it("maps low severity to SARIF level 'note'", () => {
    const path = mod.generateSarif(FULL_SCAN, "sarif-note-level");
    const sarif = JSON.parse(readFileSync(path, "utf8"));
    const lowResult = sarif.runs[0].results.find(
      (r: { ruleId: string; level: string }) => r.ruleId === "social_engineering"
    );
    expect(lowResult).toBeDefined();
    expect(lowResult.level).toBe("note");
  });

  it("rules array contains unique technique IDs from findings", () => {
    const path = mod.generateSarif(FULL_SCAN, "sarif-rules");
    const sarif = JSON.parse(readFileSync(path, "utf8"));
    const ruleIds: string[] = sarif.runs[0].tool.driver.rules.map(
      (r: { id: string }) => r.id
    );
    expect(ruleIds).toContain("direct_extraction");
    expect(ruleIds).toContain("persona_swap");
    expect(ruleIds).toContain("social_engineering");
    // No duplicates
    expect(ruleIds.length).toBe(new Set(ruleIds).size);
  });

  it("results include promptHash in artifact URI", () => {
    const path = mod.generateSarif(FULL_SCAN, "sarif-uri");
    const sarif = JSON.parse(readFileSync(path, "utf8"));
    const uri: string =
      sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
    expect(uri).toContain("deadbeef");
  });

  it("handles zero findings without throwing", () => {
    expect(() => mod.generateSarif(EMPTY_SCAN, "sarif-empty")).not.toThrow();
    const sarif = JSON.parse(readFileSync(join(tmpDir, "sarif-empty.sarif"), "utf8"));
    expect(sarif.runs[0].results).toHaveLength(0);
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(0);
  });

  it("run properties include overallVulnerability and leakStatus", () => {
    const path = mod.generateSarif(FULL_SCAN, "sarif-props");
    const sarif = JSON.parse(readFileSync(path, "utf8"));
    expect(sarif.runs[0].properties).toMatchObject({
      overallVulnerability: "high",
      leakStatus: "substantial",
    });
  });
});

describe("reports module — generateJunit", () => {
  it("creates .xml file saved to reports dir", () => {
    const path = mod.generateJunit(FULL_SCAN, "junit-001");
    expect(existsSync(path)).toBe(true);
    expect(path).toMatch(/\.xml$/);
    expect(path).toBe(join(tmpDir, "junit-001.xml"));
  });

  it("JUnit XML output is valid XML with balanced root element", () => {
    const path = mod.generateJunit(FULL_SCAN, "junit-valid");
    const xml = readFileSync(path, "utf8");
    expect(xml).toContain("<testsuites");
    expect(xml).toContain("</testsuites>");
    expect(xml.indexOf("<testsuites")).toBeLessThan(xml.indexOf("</testsuites>"));
  });

  it("<testsuites> root element has correct name attribute", () => {
    const path = mod.generateJunit(FULL_SCAN, "junit-name");
    const xml = readFileSync(path, "utf8");
    expect(xml).toContain('name="GuardX Security Scan"');
  });

  it("each finding becomes a <testcase> with correct name and classname", () => {
    const path = mod.generateJunit(FULL_SCAN, "junit-testcases");
    const xml = readFileSync(path, "utf8");
    expect(xml).toContain('name="direct_extraction');
    expect(xml).toContain('classname="guardx.direct"');
    expect(xml).toContain('classname="guardx.persona"');
    expect(xml).toContain('classname="guardx.social"');
  });

  it("critical findings produce <failure> child element", () => {
    const path = mod.generateJunit(FULL_SCAN, "junit-critical-failure");
    const xml = readFileSync(path, "utf8");
    // f1 is critical
    expect(xml).toContain('<failure type="critical"');
  });

  it("medium/low findings also produce <failure> child element (security failures)", () => {
    const path = mod.generateJunit(FULL_SCAN, "junit-med-low-failure");
    const xml = readFileSync(path, "utf8");
    expect(xml).toContain('<failure type="medium"');
    expect(xml).toContain('<failure type="low"');
  });

  it("failures attribute on <testsuite> matches critical + high count only", () => {
    const path = mod.generateJunit(FULL_SCAN, "junit-failures-count");
    const xml = readFileSync(path, "utf8");
    // FULL_SCAN has 1 critical, 0 high → failures="1"
    expect(xml).toMatch(/failures="1"/);
  });

  it("clean probes produce <testcase> with no children", () => {
    const path = mod.generateJunit(JUNIT_SCAN, "junit-clean-probes");
    const xml = readFileSync(path, "utf8");
    expect(xml).toContain('name="probe — encoding — clean"');
    expect(xml).toContain('name="probe — technical — clean"');
    // A clean probe testcase should not contain a <failure> element immediately after
    expect(xml).toContain('classname="guardx.encoding"/>');
  });

  it("special XML characters in finding content are escaped", () => {
    const path = mod.generateJunit(FULL_SCAN, "junit-escape");
    const xml = readFileSync(path, "utf8");
    // f1 extractedContent has "<assistant>" and "&"
    expect(xml).toContain("&lt;assistant&gt;");
    expect(xml).toContain("&amp;");
    expect(xml).not.toContain("<assistant>");
  });

  it("handles zero findings without throwing", () => {
    expect(() => mod.generateJunit(EMPTY_SCAN, "junit-empty")).not.toThrow();
    const xml = readFileSync(join(tmpDir, "junit-empty.xml"), "utf8");
    expect(xml).toContain('<testsuites');
    expect(xml).toContain('failures="0"');
  });
});

// ─── PDF report tests ─────────────────────────────────────────────────────────

describe("reports module — generatePdf", () => {
  it("creates the reports directory and .pdf file", async () => {
    const path = await mod.generatePdf(FULL_SCAN, "pdf-001");
    expect(existsSync(path)).toBe(true);
    expect(path).toMatch(/\.pdf$/);
  });

  it("returns the correct file path in .guardx/reports/", async () => {
    const path = await mod.generatePdf(FULL_SCAN, "pdf-path");
    expect(path).toBe(join(tmpDir, "pdf-path.pdf"));
  });

  it("output is non-empty binary (Buffer-readable file)", async () => {
    const path = await mod.generatePdf(FULL_SCAN, "pdf-nonempty");
    const buf = readFileSync(path);
    expect(buf.length).toBeGreaterThan(0);
  });

  it("output starts with %PDF- magic bytes", async () => {
    const path = await mod.generatePdf(FULL_SCAN, "pdf-magic");
    const buf = readFileSync(path);
    expect(buf.slice(0, 5).equals(PDF_MAGIC)).toBe(true);
  });

  it("handles empty findings array without throwing (generates valid PDF)", async () => {
    const path = await mod.generatePdf(EMPTY_SCAN, "pdf-empty");
    const buf = readFileSync(path);
    expect(buf.length).toBeGreaterThan(0);
    expect(buf.slice(0, 5).equals(PDF_MAGIC)).toBe(true);
  });

  it("does not throw for any vulnerability rating value", async () => {
    const ratings = ["secure", "low_risk", "medium_risk", "high_risk", "critical"];
    for (const rating of ratings) {
      await expect(
        mod.generatePdf({ ...FULL_SCAN, overallVulnerability: rating }, `pdf-rating-${rating}`)
      ).resolves.toMatch(/\.pdf$/);
    }
  });

  it("handles special characters in finding content without crashing", async () => {
    const specialScan: import("../../src/reports.js").ScanRecord = {
      ...FULL_SCAN,
      findings: [
        {
          severity: "high",
          technique: "test",
          category: "direct",
          extractedContent: "Special: <>&\"'\u2603",
          confidence: "high",
          evidence: "Special chars test.",
        },
      ],
    };
    const path = await mod.generatePdf(specialScan, "pdf-special");
    const buf = readFileSync(path);
    expect(buf.slice(0, 5).equals(PDF_MAGIC)).toBe(true);
  });

  it("PDF generation with unsorted mixed-severity findings completes — output is larger than empty-findings PDF (B2)", async () => {
    const mixedScan: import("../../src/reports.js").ScanRecord = {
      ...FULL_SCAN,
      findings: [
        { severity: "low", technique: "t1", category: "direct", evidence: "low" },
        { severity: "critical", technique: "t2", category: "direct", evidence: "crit" },
        { severity: "medium", technique: "t3", category: "direct", evidence: "med" },
        { severity: "high", technique: "t4", category: "direct", evidence: "high" },
      ],
    };
    const path = await mod.generatePdf(mixedScan, "pdf-sorted");
    const buf = readFileSync(path);
    expect(buf.slice(0, 5).equals(PDF_MAGIC)).toBe(true);
    // A scan with 4 findings must produce a larger PDF than one with 0 findings,
    // confirming findings content was written (and sort didn't silently drop items)
    const emptyPath = await mod.generatePdf(EMPTY_SCAN, "pdf-sorted-empty-ref");
    const emptyBuf = readFileSync(emptyPath);
    expect(buf.length).toBeGreaterThan(emptyBuf.length);
  });

  it("scan with no recommendations does not throw", async () => {
    const noRecs: import("../../src/reports.js").ScanRecord = {
      ...FULL_SCAN,
      recommendations: [],
    };
    await expect(mod.generatePdf(noRecs, "pdf-norecs")).resolves.toMatch(/\.pdf$/);
  });

  it("scan with undefined findings does not throw", async () => {
    const noFindings: import("../../src/reports.js").ScanRecord = {
      id: "no-findings",
      overallVulnerability: "secure",
    };
    await expect(mod.generatePdf(noFindings, "pdf-undef-findings")).resolves.toMatch(/\.pdf$/);
  });

  it("format 'pdf' accepted by generatePdf export and returns .pdf path", async () => {
    const path = await mod.generatePdf(FULL_SCAN, "pdf-format-check");
    expect(path).toMatch(/\.pdf$/);
  });

  it("PDF with findings is larger than PDF with empty findings — confirms finding content was written (B1)", async () => {
    const pathWithFindings = await mod.generatePdf(FULL_SCAN, "pdf-b1-findings");
    const pathEmpty = await mod.generatePdf(EMPTY_SCAN, "pdf-b1-empty");
    const sizeWithFindings = readFileSync(pathWithFindings).length;
    const sizeEmpty = readFileSync(pathEmpty).length;
    expect(sizeWithFindings).toBeGreaterThan(sizeEmpty);
  });

  it("extractedContent >300 chars is truncated — PDF size is similar to 300-char content (B3)", async () => {
    // Implementation: f.extractedContent.slice(0, 300) — see reports.ts
    const longContent = "x".repeat(5000);
    const shortContent = "x".repeat(300);
    const longScan: import("../../src/reports.js").ScanRecord = {
      ...FULL_SCAN,
      findings: [
        { severity: "high", technique: "t1", category: "direct", evidence: "e", extractedContent: longContent },
      ],
    };
    const shortScan: import("../../src/reports.js").ScanRecord = {
      ...FULL_SCAN,
      findings: [
        { severity: "high", technique: "t1", category: "direct", evidence: "e", extractedContent: shortContent },
      ],
    };
    const pathLong = await mod.generatePdf(longScan, "pdf-b3-long");
    const pathShort = await mod.generatePdf(shortScan, "pdf-b3-short");
    const bufLong = readFileSync(pathLong);
    const bufShort = readFileSync(pathShort);
    expect(bufLong.slice(0, 5).equals(PDF_MAGIC)).toBe(true);
    expect(bufShort.slice(0, 5).equals(PDF_MAGIC)).toBe(true);
    // Truncation at 300 chars means both PDFs should have near-identical finding text size.
    // Allow 1 KB tolerance for PDFKit stream overhead variability.
    const sizeDiff = Math.abs(bufLong.length - bufShort.length);
    expect(sizeDiff).toBeLessThan(1024);
  });

  it("existing html, sarif, junit formats still produce correct file types — no regression", () => {
    const htmlPath = mod.generateHtml(FULL_SCAN, "regression-html");
    const sarifPath = mod.generateSarif(FULL_SCAN, "regression-sarif");
    const junitPath = mod.generateJunit(FULL_SCAN, "regression-junit");
    expect(htmlPath).toMatch(/\.html$/);
    expect(sarifPath).toMatch(/\.sarif$/);
    expect(junitPath).toMatch(/\.xml$/);
    expect(existsSync(htmlPath)).toBe(true);
    expect(existsSync(sarifPath)).toBe(true);
    expect(existsSync(junitPath)).toBe(true);
  });
});
