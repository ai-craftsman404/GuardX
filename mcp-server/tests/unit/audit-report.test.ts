import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import { generateAuditReport, AuditReportResult } from "../../src/audit-report.js";
import type { ScanFinding } from "../../src/scanner.js";

const TEST_DIR = path.join(process.cwd(), ".guardx-test-audit");

beforeEach(() => {
  if (!fs.existsSync(TEST_DIR)) {
    fs.mkdirSync(TEST_DIR, { recursive: true });
  }
});

afterEach(() => {
  if (fs.existsSync(TEST_DIR)) {
    fs.rmSync(TEST_DIR, { recursive: true, force: true });
  }
});

function createMockFinding(
  category: string,
  technique: string,
  severity: "critical" | "high" | "medium" | "low"
): ScanFinding {
  return {
    category,
    technique,
    severity,
    confidence: 0.9,
    description: `Finding: ${technique}`,
    evidence: `Evidence for ${technique}`,
    recommendation: `Fix ${technique}`,
  };
}

describe("audit-report", () => {
  it("handles empty findings gracefully", async () => {
    const result = await generateAuditReport(
      [],
      "soc2",
      "json",
      "TestOrg",
      TEST_DIR
    );

    expect(result).toBeDefined();
    expect(result.controlsMapped).toBe(0);
    expect(result.controlsFailed).toBe(0);
    expect(fs.existsSync(result.reportPath)).toBe(true);
  });

  it("produces JSON format with correct structure", async () => {
    const findings = [createMockFinding("cat1", "prompt-injection", "critical")];

    const result = await generateAuditReport(
      findings,
      "soc2",
      "json",
      "TestOrg",
      TEST_DIR
    );

    expect(result.reportPath).toMatch(/\.json$/);
    expect(fs.existsSync(result.reportPath)).toBe(true);

    const content = fs.readFileSync(result.reportPath, "utf-8");
    const data = JSON.parse(content);

    expect(data).toHaveProperty("framework");
    expect(data).toHaveProperty("controls");
    expect(data).toHaveProperty("organization");
  });

  it("produces HTML format with correct structure", async () => {
    const findings = [createMockFinding("cat1", "prompt-injection", "high")];

    const result = await generateAuditReport(
      findings,
      "iso27001",
      "html",
      "TestOrg",
      TEST_DIR
    );

    expect(result.reportPath).toMatch(/\.html$/);
    expect(fs.existsSync(result.reportPath)).toBe(true);

    const content = fs.readFileSync(result.reportPath, "utf-8");
    expect(content).toMatch(/<html/i);
    expect(content).toContain("TestOrg");
  });

  it("produces CSV format", async () => {
    const findings = [createMockFinding("cat1", "data-poisoning", "medium")];

    const result = await generateAuditReport(
      findings,
      "nist-ai-rmf",
      "csv",
      undefined,
      TEST_DIR
    );

    expect(result.reportPath).toMatch(/\.csv$/);
    expect(fs.existsSync(result.reportPath)).toBe(true);

    const content = fs.readFileSync(result.reportPath, "utf-8");
    expect(content).toContain(","); // CSV should have commas
  });

  it("maps SOC2 framework correctly", async () => {
    const findings = [createMockFinding("access_control", "prompt-injection", "critical")];

    const result = await generateAuditReport(
      findings,
      "soc2",
      "json",
      "TestOrg",
      TEST_DIR
    );

    const content = fs.readFileSync(result.reportPath, "utf-8");
    const data = JSON.parse(content);

    expect(data.framework).toBe("soc2");
    expect(result.controlsMapped).toBeGreaterThan(0);
    expect(result.controlsFailed).toBeGreaterThan(0);
  });

  it("maps ISO 27001 framework correctly", async () => {
    const findings = [createMockFinding("encryption", "data-poisoning", "high")];

    const result = await generateAuditReport(
      findings,
      "iso27001",
      "json",
      "TestOrg",
      TEST_DIR
    );

    const content = fs.readFileSync(result.reportPath, "utf-8");
    const data = JSON.parse(content);

    expect(data.framework).toBe("iso27001");
    expect(result.controlsMapped).toBeGreaterThan(0);
  });

  it("maps NIST AI RMF framework correctly", async () => {
    const findings = [createMockFinding("governance", "agent-escalation", "critical")];

    const result = await generateAuditReport(
      findings,
      "nist-ai-rmf",
      "json",
      "TestOrg",
      TEST_DIR
    );

    const content = fs.readFileSync(result.reportPath, "utf-8");
    const data = JSON.parse(content);

    expect(data.framework).toBe("nist-ai-rmf");
  });

  it("generates 'all' frameworks in single report", async () => {
    const findings = [
      createMockFinding("security", "prompt-injection", "critical"),
      createMockFinding("access", "data-poisoning", "high"),
    ];

    const result = await generateAuditReport(
      findings,
      "all",
      "json",
      "TestOrg",
      TEST_DIR
    );

    const content = fs.readFileSync(result.reportPath, "utf-8");
    const data = JSON.parse(content);

    expect(data.framework).toBe("all");
    expect(result.controlsMapped).toBeGreaterThan(0);
  });

  it("counts controlsFailed correctly for non-empty findings", async () => {
    const findings = [
      createMockFinding("cat1", "prompt-injection", "critical"),
      createMockFinding("cat2", "data-poisoning", "high"),
      createMockFinding("cat3", "agent-escalation", "medium"),
    ];

    const result = await generateAuditReport(
      findings,
      "soc2",
      "json",
      "TestOrg",
      TEST_DIR
    );

    expect(result.controlsFailed).toBeGreaterThan(0);
    expect(result.controlsMapped).toBeGreaterThan(0);
  });

  it("includes organizationName in output when provided", async () => {
    const findings = [createMockFinding("cat1", "prompt-injection", "high")];
    const orgName = "AcmeCorp Industries";

    const result = await generateAuditReport(
      findings,
      "soc2",
      "html",
      orgName,
      TEST_DIR
    );

    const content = fs.readFileSync(result.reportPath, "utf-8");
    expect(content).toContain(orgName);
  });

  it("handles multiple output formats for same findings", async () => {
    const findings = [
      createMockFinding("cat1", "prompt-injection", "critical"),
      createMockFinding("cat2", "data-poisoning", "high"),
    ];

    const jsonResult = await generateAuditReport(
      findings,
      "soc2",
      "json",
      "TestOrg",
      TEST_DIR
    );
    const htmlResult = await generateAuditReport(
      findings,
      "soc2",
      "html",
      "TestOrg",
      TEST_DIR
    );
    const csvResult = await generateAuditReport(
      findings,
      "soc2",
      "csv",
      "TestOrg",
      TEST_DIR
    );

    expect(fs.existsSync(jsonResult.reportPath)).toBe(true);
    expect(fs.existsSync(htmlResult.reportPath)).toBe(true);
    expect(fs.existsSync(csvResult.reportPath)).toBe(true);

    // All should have same control mapping counts
    expect(jsonResult.controlsMapped).toBe(htmlResult.controlsMapped);
    expect(jsonResult.controlsMapped).toBe(csvResult.controlsMapped);
  });

  it("includes executive summary", async () => {
    const findings = [createMockFinding("cat1", "prompt-injection", "critical")];

    const result = await generateAuditReport(
      findings,
      "soc2",
      "json",
      "TestOrg",
      TEST_DIR
    );

    expect(result.executiveSummary).toBeDefined();
    expect(result.executiveSummary).toMatch(/control|finding|risk/i);
  });

  it("maps findings to correct controls in each framework", async () => {
    const findings = [
      createMockFinding("system_prompt_extraction", "prompt-injection", "critical"),
    ];

    const soc2Result = await generateAuditReport(
      findings,
      "soc2",
      "json",
      "TestOrg",
      TEST_DIR
    );
    const iso27001Result = await generateAuditReport(
      findings,
      "iso27001",
      "json",
      "TestOrg",
      TEST_DIR
    );
    const nistResult = await generateAuditReport(
      findings,
      "nist-ai-rmf",
      "json",
      "TestOrg",
      TEST_DIR
    );

    // Each should have mapped controls
    expect(soc2Result.controlsMapped).toBeGreaterThan(0);
    expect(iso27001Result.controlsMapped).toBeGreaterThan(0);
    expect(nistResult.controlsMapped).toBeGreaterThan(0);
  });

  it("respects outputPath override", async () => {
    const customPath = path.join(TEST_DIR, "custom-reports");
    fs.mkdirSync(customPath, { recursive: true });

    const findings = [createMockFinding("cat1", "prompt-injection", "high")];
    const result = await generateAuditReport(
      findings,
      "soc2",
      "json",
      "TestOrg",
      customPath
    );

    expect(result.reportPath).toContain(customPath);
    expect(fs.existsSync(result.reportPath)).toBe(true);
  });
});
