import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "fs";
import * as path from "path";
import { generateTrendDashboard, DashboardResult } from "../../src/dashboard.js";
import type { ScanResult, ScanFinding } from "../../src/scanner.js";

const TEST_DIR = path.join(process.cwd(), ".guardx-test");

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

function createMockScanResult(
  findingCount: number,
  timestamp: string,
  severity: "critical" | "high" | "medium" | "low" = "high"
): ScanResult {
  const findings: ScanFinding[] = [];
  const techniques = [
    "prompt-injection",
    "data-poisoning",
    "agent-escalation",
    "context-confusion",
    "semantic-override",
  ];

  for (let i = 0; i < findingCount; i++) {
    findings.push({
      category: `category-${i % 3}`,
      technique: techniques[i % techniques.length],
      severity,
      confidence: 0.85,
      description: `Finding ${i}`,
      evidence: `Evidence ${i}`,
      recommendation: `Recommendation ${i}`,
    });
  }

  return {
    findings,
    vulnerability: severity,
    leakStatus: "none",
    recommendations: [],
    defenseProfiles: [],
    totalTokens: 1000,
    scanId: `scan-${timestamp}`,
    timestamp,
  };
}

describe("dashboard", () => {
  it("empty scanResults returns graceful empty state", async () => {
    const result = await generateTrendDashboard([], TEST_DIR);

    expect(result).toMatchObject({
      scansIncluded: 0,
      riskTrend: "stable",
      topRecurringTechniques: [],
    });
    expect(result.dashboardPath).toMatch(/dashboard\.html$/);
  });

  it("single scan returns stable trend with no delta", async () => {
    const scan = createMockScanResult(3, "2026-04-30T10:00:00Z", "high");
    const result = await generateTrendDashboard([scan], TEST_DIR);

    expect(result.scansIncluded).toBe(1);
    expect(result.riskTrend).toBe("stable");
  });

  it("3 scans with decreasing severity counts shows improving trend", async () => {
    const scans = [
      createMockScanResult(10, "2026-04-28T10:00:00Z", "critical"),
      createMockScanResult(7, "2026-04-29T10:00:00Z", "high"),
      createMockScanResult(5, "2026-04-30T10:00:00Z", "medium"),
    ];
    const result = await generateTrendDashboard(scans, TEST_DIR);

    expect(result.scansIncluded).toBe(3);
    expect(result.riskTrend).toBe("improving");
  });

  it("3 scans with increasing severity counts shows degrading trend", async () => {
    const scans = [
      createMockScanResult(3, "2026-04-28T10:00:00Z", "low"),
      createMockScanResult(6, "2026-04-29T10:00:00Z", "medium"),
      createMockScanResult(10, "2026-04-30T10:00:00Z", "high"),
    ];
    const result = await generateTrendDashboard(scans, TEST_DIR);

    expect(result.scansIncluded).toBe(3);
    expect(result.riskTrend).toBe("degrading");
  });

  it("topRecurringTechniques includes only techniques in >50% of scans", async () => {
    const findings1: ScanFinding[] = [
      {
        category: "cat1",
        technique: "prompt-injection",
        severity: "high",
        confidence: 0.9,
        description: "desc",
        evidence: "ev",
        recommendation: "rec",
      },
      {
        category: "cat2",
        technique: "data-poisoning",
        severity: "high",
        confidence: 0.9,
        description: "desc",
        evidence: "ev",
        recommendation: "rec",
      },
    ];

    const findings2: ScanFinding[] = [
      {
        category: "cat1",
        technique: "prompt-injection",
        severity: "high",
        confidence: 0.9,
        description: "desc",
        evidence: "ev",
        recommendation: "rec",
      },
      {
        category: "cat3",
        technique: "agent-escalation",
        severity: "high",
        confidence: 0.9,
        description: "desc",
        evidence: "ev",
        recommendation: "rec",
      },
    ];

    const findings3: ScanFinding[] = [
      {
        category: "cat1",
        technique: "prompt-injection",
        severity: "high",
        confidence: 0.9,
        description: "desc",
        evidence: "ev",
        recommendation: "rec",
      },
      {
        category: "cat4",
        technique: "context-confusion",
        severity: "high",
        confidence: 0.9,
        description: "desc",
        evidence: "ev",
        recommendation: "rec",
      },
    ];

    const scans: ScanResult[] = [
      { ...createMockScanResult(0, "2026-04-28T10:00:00Z"), findings: findings1 },
      { ...createMockScanResult(0, "2026-04-29T10:00:00Z"), findings: findings2 },
      { ...createMockScanResult(0, "2026-04-30T10:00:00Z"), findings: findings3 },
    ];

    const result = await generateTrendDashboard(scans, TEST_DIR);

    // prompt-injection appears in 3/3 (100%), data-poisoning in 1/3 (33%), agent-escalation in 1/3, context-confusion in 1/3
    expect(result.topRecurringTechniques).toContain("prompt-injection");
    expect(result.topRecurringTechniques).not.toContain("data-poisoning");
    expect(result.topRecurringTechniques).not.toContain("agent-escalation");
    expect(result.topRecurringTechniques).not.toContain("context-confusion");
  });

  it("writes HTML file to disk with scan count", async () => {
    const scans = [
      createMockScanResult(3, "2026-04-28T10:00:00Z"),
      createMockScanResult(5, "2026-04-29T10:00:00Z"),
      createMockScanResult(4, "2026-04-30T10:00:00Z"),
    ];

    const result = await generateTrendDashboard(scans, TEST_DIR);

    expect(fs.existsSync(result.dashboardPath)).toBe(true);

    const htmlContent = fs.readFileSync(result.dashboardPath, "utf-8");
    expect(htmlContent).toMatch(/<html/i);
    expect(htmlContent).toContain("3"); // scans included count
  });

  it("respects outputPath override", async () => {
    const customPath = path.join(TEST_DIR, "custom");
    fs.mkdirSync(customPath, { recursive: true });

    const scans = [createMockScanResult(2, "2026-04-30T10:00:00Z")];
    const result = await generateTrendDashboard(scans, customPath);

    expect(result.dashboardPath).toContain(customPath);
    expect(fs.existsSync(result.dashboardPath)).toBe(true);
  });

  it("scansIncluded matches input array length", async () => {
    const scans = [
      createMockScanResult(2, "2026-04-28T10:00:00Z"),
      createMockScanResult(3, "2026-04-29T10:00:00Z"),
      createMockScanResult(4, "2026-04-30T10:00:00Z"),
      createMockScanResult(5, "2026-05-01T10:00:00Z"),
      createMockScanResult(6, "2026-05-02T10:00:00Z"),
    ];

    const result = await generateTrendDashboard(scans, TEST_DIR);

    expect(result.scansIncluded).toBe(5);
  });
});
