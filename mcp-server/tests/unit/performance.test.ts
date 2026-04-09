import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { diffScanObjects } from "../../src/diff.js";
import { generateJunit, generateHtml, generateSarif } from "../../src/reports.js";
import type { ScanRecord } from "../../src/reports.js";

type Finding = {
  id?: string;
  severity?: string;
  technique?: string;
  category?: string;
  extractedContent?: string;
  confidence?: string;
  evidence?: string;
};

let tempDir: string;

beforeEach(() => {
  tempDir = mkdtempSync(join(tmpdir(), "guardx-perf-"));
  process.env.GUARDX_REPORTS_DIR = tempDir;
});

afterEach(() => {
  rmSync(tempDir, { recursive: true, force: true });
  delete process.env.GUARDX_REPORTS_DIR;
});

function makeFindings(n: number): Finding[] {
  return Array.from({ length: n }, (_, i) => ({
    id: `f${i}`,
    severity: ["critical", "high", "medium", "low"][i % 4],
    technique: `technique_${i % 10}`,
    category: `category_${i % 5}`,
    extractedContent: `Extracted content for finding ${i} — some longer text here to be realistic`,
    confidence: ["high", "medium", "low"][i % 3],
    evidence: `Evidence for finding ${i}`,
  }));
}

describe("performance — timing thresholds", () => {
  it("diffScanObjects — 50 findings completes under 50ms", () => {
    const baseline: ScanRecord = {
      findings: makeFindings(50),
      overallVulnerability: "high",
    };

    // Create current with 25 shared, 25 new
    const currentFindings = makeFindings(25).concat(
      Array.from({ length: 25 }, (_, i) => ({
        id: `f${50 + i}`,
        severity: "high",
        technique: `technique_new_${i}`,
        category: "new_category",
        extractedContent: `New finding ${i}`,
        confidence: "high",
        evidence: `New evidence ${i}`,
      }))
    );

    const current: ScanRecord = {
      findings: currentFindings,
      overallVulnerability: "critical",
    };

    const start = Date.now();
    const result = diffScanObjects(baseline, current);
    const elapsed = Date.now() - start;

    expect(elapsed).toBeLessThan(50);
    // total unique-key findings in current = persisting + new
    expect(result.newFindings.length + result.persistingFindings.length).toBeGreaterThan(0);
  });

  it("diffScanObjects — 200 findings completes under 100ms", () => {
    const baseline: ScanRecord = {
      findings: makeFindings(200),
      overallVulnerability: "high",
    };

    // Create current with 100 shared, 100 new
    const currentFindings = makeFindings(100).concat(
      Array.from({ length: 100 }, (_, i) => ({
        id: `f${200 + i}`,
        severity: "high",
        technique: `technique_new_${i}`,
        category: "new_category",
        extractedContent: `New finding ${i}`,
        confidence: "high",
        evidence: `New evidence ${i}`,
      }))
    );

    const current: ScanRecord = {
      findings: currentFindings,
      overallVulnerability: "critical",
    };

    const start = Date.now();
    const result = diffScanObjects(baseline, current);
    const elapsed = Date.now() - start;

    expect(elapsed).toBeLessThan(100);
    expect(result.newFindings.length).toBeGreaterThan(0);
    expect(result.persistingFindings.length).toBeGreaterThan(0);
  });

  it("generateJunit — 100 findings completes under 500ms", () => {
    const scan: ScanRecord = {
      id: "scan-junit-100",
      findings: makeFindings(100),
      cleanProbeCategories: Array.from({ length: 10 }, (_, i) => `category_${i}`),
      recommendations: [
        "Recommendation 1",
        "Recommendation 2",
        "Recommendation 3",
        "Recommendation 4",
        "Recommendation 5",
      ],
      duration: 5000,
    };

    const start = Date.now();
    const path = generateJunit(scan, "junit-100");
    const elapsed = Date.now() - start;

    expect(elapsed).toBeLessThan(500);
    expect(path).toMatch(/\.xml$/);
  });

  it("generateHtml — 100 findings completes under 500ms", () => {
    const scan: ScanRecord = {
      id: "scan-html-100",
      findings: makeFindings(100),
      cleanProbeCategories: Array.from({ length: 10 }, (_, i) => `category_${i}`),
      recommendations: [
        "Recommendation 1",
        "Recommendation 2",
        "Recommendation 3",
        "Recommendation 4",
        "Recommendation 5",
      ],
      duration: 5000,
    };

    const start = Date.now();
    const path = generateHtml(scan, "html-100");
    const elapsed = Date.now() - start;

    expect(elapsed).toBeLessThan(500);
    expect(path).toMatch(/\.html$/);
  });

  it("generateSarif — 100 findings completes under 500ms", () => {
    const scan: ScanRecord = {
      id: "scan-sarif-100",
      findings: makeFindings(100),
      cleanProbeCategories: Array.from({ length: 10 }, (_, i) => `category_${i}`),
      recommendations: [
        "Recommendation 1",
        "Recommendation 2",
        "Recommendation 3",
        "Recommendation 4",
        "Recommendation 5",
      ],
      duration: 5000,
    };

    const start = Date.now();
    const path = generateSarif(scan, "sarif-100");
    const elapsed = Date.now() - start;

    expect(elapsed).toBeLessThan(500);
    expect(path).toMatch(/\.sarif$/);
  });

  it("diffScanObjects — empty vs 100 findings (worst case regression) completes under 100ms", () => {
    const baseline: ScanRecord = {
      findings: [],
      overallVulnerability: "low",
    };

    // Use fully unique technique+category per finding so all 100 are distinct keys
    const uniqueFindings: Finding[] = Array.from({ length: 100 }, (_, i) => ({
      id: `f${i}`,
      severity: "high",
      technique: `unique_technique_${i}`,
      category: `unique_category_${i}`,
      extractedContent: `content ${i}`,
      confidence: "high",
      evidence: `evidence ${i}`,
    }));

    const current: ScanRecord = {
      findings: uniqueFindings,
      overallVulnerability: "critical",
    };

    const start = Date.now();
    const result = diffScanObjects(baseline, current);
    const elapsed = Date.now() - start;

    expect(elapsed).toBeLessThan(100);
    expect(result.newFindings.length).toBe(100);
    expect(result.regressionDetected).toBe(true);
  });

  it("generateJunit — 500 findings stress test completes under 2000ms", () => {
    const scan: ScanRecord = {
      id: "scan-junit-500",
      findings: makeFindings(500),
      cleanProbeCategories: Array.from({ length: 10 }, (_, i) => `category_${i}`),
      recommendations: [
        "Recommendation 1",
        "Recommendation 2",
        "Recommendation 3",
        "Recommendation 4",
        "Recommendation 5",
      ],
      duration: 10000,
    };

    const start = Date.now();
    const path = generateJunit(scan, "junit-500");
    const elapsed = Date.now() - start;

    expect(elapsed).toBeLessThan(2000);
    expect(path).toMatch(/\.xml$/);
  });
});
