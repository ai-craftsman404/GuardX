import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { generateJunit, generateHtml, generateSarif } from "../../src/reports.js";
import type { ScanRecord, Finding } from "../../src/reports.js";

function makeScan(overrides?: Partial<ScanRecord>): ScanRecord {
  return {
    id: "scan-001",
    findings: [],
    recommendations: ["Use guardrails", "Apply defense strategies"],
    duration: 5000,
    ...overrides,
  };
}

describe("report validity — JUnit XML", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "guardx-test-"));
    process.env.GUARDX_REPORTS_DIR = tempDir;
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
    delete process.env.GUARDX_REPORTS_DIR;
  });

  it("well-formed XML: starts with declaration and has matching root tags", () => {
    const scan = makeScan({
      findings: [
        {
          id: "f1",
          severity: "critical",
          technique: "direct_injection",
          category: "injection",
          extractedContent: "injected prompt",
          confidence: "high",
        },
        {
          id: "f2",
          severity: "medium",
          technique: "social_engineering",
          category: "persona",
          extractedContent: "social attack",
          confidence: "medium",
        },
      ],
    });

    const filePath = generateJunit(scan, "test-junit");
    const content = readFileSync(filePath, "utf-8");

    expect(content).toMatch(/^<\?xml version="1\.0" encoding="UTF-8"\?>/);
    expect(content).toContain("<testsuites");
    expect(content).toContain("</testsuites>");

    // Ensure well-formed: testsuite (not testsuites) open/close tags match
    const testsuiteOpen = (content.match(/<testsuite[^s]/g) || []).length;
    const testsuiteClose = (content.match(/<\/testsuite>/g) || []).length;
    expect(testsuiteOpen).toBe(testsuiteClose);
  });

  it("failures attribute equals count of critical+high findings only", () => {
    const scan = makeScan({
      findings: [
        { severity: "critical", technique: "tech1", category: "cat1" },
        { severity: "high", technique: "tech2", category: "cat2" },
        { severity: "medium", technique: "tech3", category: "cat3" },
        { severity: "low", technique: "tech4", category: "cat4" },
      ],
    });

    const filePath = generateJunit(scan, "test-failures");
    const content = readFileSync(filePath, "utf-8");

    const failuresMatch = content.match(/failures="(\d+)"/);
    expect(failuresMatch).toBeTruthy();
    expect(failuresMatch?.[1]).toBe("2");
  });

  it("special chars in finding content are escaped: &, <, >, double-quote", () => {
    const scan = makeScan({
      findings: [
        {
          severity: "high",
          technique: "escape_test",
          category: "testing",
          extractedContent: 'You & I <said> "hello"',
          confidence: "high",
        },
      ],
    });

    const filePath = generateJunit(scan, "test-escape");
    const content = readFileSync(filePath, "utf-8");

    // Check that raw unescaped characters don't appear in dangerous contexts
    // Verify &amp; is used instead of bare &
    expect(content).toContain("&amp;");
    expect(content).not.toMatch(/You & I /);

    // Verify &lt; and &gt; are used
    expect(content).toContain("&lt;");
    expect(content).toContain("&gt;");
    expect(content).not.toContain("<said>");

    // Verify &quot; is used for quotes in attributes
    expect(content).toContain("&quot;");
  });

  it("zero findings scan → output contains failures=\"0\" and tests=\"0\"", () => {
    const scan = makeScan({ findings: [] });
    const filePath = generateJunit(scan, "test-zero");
    const content = readFileSync(filePath, "utf-8");

    expect(content).toMatch(/failures="0"/);
    expect(content).toMatch(/tests="0"/);
  });
});

describe("report validity — SARIF JSON", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "guardx-test-"));
    process.env.GUARDX_REPORTS_DIR = tempDir;
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
    delete process.env.GUARDX_REPORTS_DIR;
  });

  it("valid JSON with $schema and version 2.1.0", () => {
    const scan = makeScan({
      findings: [
        {
          severity: "critical",
          technique: "prompt_injection",
          category: "injection",
        },
      ],
    });

    const filePath = generateSarif(scan, "test-sarif");
    const content = readFileSync(filePath, "utf-8");
    const result = JSON.parse(content);

    expect(result.$schema).toMatch(/sarif/i);
    expect(result.version).toBe("2.1.0");
  });

  it("runs[0].tool.driver.name === 'GuardX'", () => {
    const scan = makeScan({
      findings: [
        {
          severity: "high",
          technique: "encoding_attack",
          category: "encoding",
        },
      ],
    });

    const filePath = generateSarif(scan, "test-driver");
    const content = readFileSync(filePath, "utf-8");
    const result = JSON.parse(content);

    expect(result.runs[0].tool.driver.name).toBe("GuardX");
  });

  it("runs[0].results is an array with length matching the number of findings", () => {
    const scan = makeScan({
      findings: [
        {
          severity: "critical",
          technique: "prompt_injection",
          category: "injection",
        },
      ],
    });

    const filePath = generateSarif(scan, "test-results");
    const content = readFileSync(filePath, "utf-8");
    const result = JSON.parse(content);

    expect(Array.isArray(result.runs[0].results)).toBe(true);
    expect(result.runs[0].results).toHaveLength(1);
  });
});

describe("report validity — HTML", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "guardx-test-"));
    process.env.GUARDX_REPORTS_DIR = tempDir;
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
    delete process.env.GUARDX_REPORTS_DIR;
  });

  it("injected script tag in finding is escaped — no raw <script> in output from finding content", () => {
    const scan = makeScan({
      findings: [
        {
          severity: "critical",
          technique: "xss_attempt",
          category: "injection",
          extractedContent: "<script>alert(1)</script>",
          confidence: "high",
        },
      ],
    });

    const filePath = generateHtml(scan, "test-xss");
    const content = readFileSync(filePath, "utf-8");

    // Ensure the literal malicious script tag does not appear raw in output
    expect(content).not.toContain("<script>alert(1)</script>");

    // Verify it's properly escaped
    expect(content).toContain("&lt;script&gt;");
  });

  it("zero findings scan → output is a non-empty string containing <html, no crash", () => {
    const scan = makeScan({ findings: [] });
    const filePath = generateHtml(scan, "test-zero-html");
    const content = readFileSync(filePath, "utf-8");

    expect(typeof content).toBe("string");
    expect(content.length).toBeGreaterThan(0);
    expect(content).toContain("<html");
  });
});
