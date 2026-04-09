import { describe, it, expect } from "vitest";
import { diffScanObjects, diffScans } from "../../src/diff.js";

const FINDING_A = {
  technique: "direct_extraction",
  category: "direct",
  contentType: "system_prompt",
  severity: "critical",
  extractedContent: "my secret prompt",
  id: "f1",
};

const FINDING_B = {
  technique: "persona_swap",
  category: "persona",
  contentType: "instructions",
  severity: "high",
  extractedContent: "persona data",
  id: "f2",
};

const FINDING_C = {
  technique: "social_engineering",
  category: "social",
  contentType: "partial",
  severity: "low",
  extractedContent: "minor leak",
  id: "f3",
};

describe("diff — diffScanObjects", () => {
  it("identical scans return empty newFindings and resolvedFindings", () => {
    const scan = { findings: [FINDING_A], overallVulnerability: "critical" };
    const result = diffScanObjects(scan, scan);
    expect(result.newFindings).toHaveLength(0);
    expect(result.resolvedFindings).toHaveLength(0);
    expect(result.persistingFindings).toHaveLength(1);
  });

  it("new critical finding sets regressionDetected: true", () => {
    const baseline = { findings: [], overallVulnerability: "secure" };
    const current = { findings: [FINDING_A], overallVulnerability: "critical" };
    const result = diffScanObjects(baseline, current);
    expect(result.newFindings).toHaveLength(1);
    expect(result.regressionDetected).toBe(true);
  });

  it("new high finding sets regressionDetected: true", () => {
    const baseline = { findings: [], overallVulnerability: "secure" };
    const current = { findings: [FINDING_B], overallVulnerability: "high_risk" };
    const result = diffScanObjects(baseline, current);
    expect(result.regressionDetected).toBe(true);
  });

  it("new low finding does not set regressionDetected: true", () => {
    const baseline = { findings: [], overallVulnerability: "secure" };
    const current = { findings: [FINDING_C], overallVulnerability: "low_risk" };
    const result = diffScanObjects(baseline, current);
    expect(result.regressionDetected).toBe(false);
  });

  it("new \"medium\" severity finding → regressionDetected: false", () => {
    const baseline = { findings: [], overallVulnerability: "secure" };
    const mediumFinding = { ...FINDING_C, severity: "medium" };
    const current = { findings: [mediumFinding], overallVulnerability: "medium_risk" };
    const result = diffScanObjects(baseline, current);
    expect(result.regressionDetected).toBe(false);
  });

  it("correctly identifies resolved findings (in baseline, not in current)", () => {
    const baseline = { findings: [FINDING_A, FINDING_B], overallVulnerability: "critical" };
    const current = { findings: [FINDING_B], overallVulnerability: "high_risk" };
    const result = diffScanObjects(baseline, current);
    expect(result.resolvedFindings).toHaveLength(1);
    expect(result.resolvedFindings[0].technique).toBe("direct_extraction");
    expect(result.newFindings).toHaveLength(0);
  });

  it("correctly identifies persisting findings (in both)", () => {
    const baseline = { findings: [FINDING_A, FINDING_B], overallVulnerability: "critical" };
    const current = { findings: [FINDING_B, FINDING_C], overallVulnerability: "high_risk" };
    const result = diffScanObjects(baseline, current);
    expect(result.persistingFindings).toHaveLength(1);
    expect(result.persistingFindings[0].technique).toBe("persona_swap");
    expect(result.newFindings).toHaveLength(1);
    expect(result.newFindings[0].technique).toBe("social_engineering");
    expect(result.resolvedFindings).toHaveLength(1);
    expect(result.resolvedFindings[0].technique).toBe("direct_extraction");
  });

  it("vulnerabilityDelta reflects change e.g. 'secure → high_risk'", () => {
    const baseline = { findings: [], overallVulnerability: "secure" };
    const current = { findings: [FINDING_B], overallVulnerability: "high_risk" };
    const result = diffScanObjects(baseline, current);
    expect(result.vulnerabilityDelta).toBe("secure → high_risk");
  });

  it("vulnerabilityDelta contains both ratings when level is unchanged", () => {
    const scan = { findings: [FINDING_C], overallVulnerability: "low_risk" };
    const result = diffScanObjects(scan, scan);
    expect(result.vulnerabilityDelta).toBe("low_risk → low_risk (unchanged)");
  });

  it("dedup matches findings by technique + category + contentType, not by id", () => {
    const f1 = { ...FINDING_A, id: "id-old" };
    const f2 = { ...FINDING_A, id: "id-new" };
    const baseline = { findings: [f1], overallVulnerability: "critical" };
    const current = { findings: [f2], overallVulnerability: "critical" };
    const result = diffScanObjects(baseline, current);
    expect(result.newFindings).toHaveLength(0);
    expect(result.persistingFindings).toHaveLength(1);
    expect(result.resolvedFindings).toHaveLength(0);
  });

  it("summary is a non-empty string", () => {
    const baseline = { findings: [FINDING_A], overallVulnerability: "critical" };
    const current = { findings: [], overallVulnerability: "secure" };
    const result = diffScanObjects(baseline, current);
    expect(typeof result.summary).toBe("string");
    expect(result.summary.length).toBeGreaterThan(0);
  });

  it("empty baseline vs empty current returns no changes", () => {
    const empty = { findings: [], overallVulnerability: "secure" };
    const result = diffScanObjects(empty, empty);
    expect(result.newFindings).toHaveLength(0);
    expect(result.resolvedFindings).toHaveLength(0);
    expect(result.persistingFindings).toHaveLength(0);
    expect(result.regressionDetected).toBe(false);
    expect(result.summary).toContain("No changes");
  });
});

describe("diff — diffScans validation", () => {
  it("missing baselineScanId throws descriptive error", async () => {
    await expect(diffScans({ baselineScanId: "" })).rejects.toThrow(/baselineScanId/i);
  });

  it("both currentScanId and systemPrompt throws mutually exclusive error", async () => {
    await expect(
      diffScans({ baselineScanId: "base-1", currentScanId: "cur-1", systemPrompt: "prompt" })
    ).rejects.toThrow(/mutually exclusive/i);
  });

  it("non-existent baselineScanId throws not found error", async () => {
    await expect(
      diffScans({ baselineScanId: "definitely-does-not-exist-xyz-12345" })
    ).rejects.toThrow(/not found/i);
  });
});
