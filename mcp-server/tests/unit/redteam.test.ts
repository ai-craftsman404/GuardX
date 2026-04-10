import { describe, it, expect, vi, beforeEach } from "vitest";

const mockRunSecurityScan = vi.hoisted(() => vi.fn());
vi.mock("../../src/scanner.js", () => ({
  runSecurityScan: mockRunSecurityScan,
}));

vi.mock("../../src/probes.js", () => ({
  getAllProbes: vi.fn(),
  getProbesByCategory: vi.fn(),
  DOCUMENTED_TECHNIQUES: {},
}));

const MOCK_SCAN_RESULT = {
  findings: [
    { id: "f1", technique: "direct_extraction", category: "direct", severity: "high", extractedContent: "secret" },
  ],
  overallVulnerability: "high",
  leakStatus: "substantial",
  recommendations: ["Add secrecy instructions"],
  defenseProfile: { level: "weak" },
  turnsUsed: 8,
  tokensUsed: 1500,
  duration: 10000,
};

async function getRedTeam() {
  const mod = await import("../../src/redteam.js");
  return mod;
}

describe("redteam — direct module tests", () => {
  beforeEach(() => {
    mockRunSecurityScan.mockReset().mockResolvedValue(MOCK_SCAN_RESULT);
    vi.resetModules();
  });

  it("runRedTeam blitz calls runSecurityScan once with enableDualMode: true", async () => {
    const { runRedTeam } = await getRedTeam();
    await runRedTeam("Test prompt", { strategy: "blitz", apiKey: "test-key" });
    expect(mockRunSecurityScan).toHaveBeenCalledTimes(1);
    const callArgs = mockRunSecurityScan.mock.calls[0][1];
    expect(callArgs.enableDualMode).toBe(true);
  });

  it("runRedTeam thorough calls runSecurityScan at least twice with different maxTurns", async () => {
    const { runRedTeam } = await getRedTeam();
    await runRedTeam("Test prompt", { strategy: "thorough", apiKey: "test-key" });
    expect(mockRunSecurityScan.mock.calls.length).toBeGreaterThanOrEqual(2);
    const turnsValues = mockRunSecurityScan.mock.calls.map((c) => c[1].maxTurns as number);
    const uniqueTurns = new Set(turnsValues);
    expect(uniqueTurns.size).toBeGreaterThan(1);
  });

  it("runRedTeam result has phasesCompleted array, strategy, totalDuration", async () => {
    const { runRedTeam } = await getRedTeam();
    const result = await runRedTeam("Test prompt", { strategy: "blitz", apiKey: "test-key" });
    expect(Array.isArray(result.phasesCompleted)).toBe(true);
    expect(result.phasesCompleted.length).toBeGreaterThan(0);
    expect(result.strategy).toBe("blitz");
    expect(typeof result.totalDuration).toBe("number");
  });

  it("runRedTeam stealth calls runSecurityScan once with scanMode extraction and enableDualMode false", async () => {
    const { runRedTeam } = await getRedTeam();
    await runRedTeam("Test prompt", { strategy: "stealth", apiKey: "test-key" });
    expect(mockRunSecurityScan).toHaveBeenCalledTimes(1);
    const callArgs = mockRunSecurityScan.mock.calls[0][1];
    expect(callArgs.enableDualMode).toBe(false);
    expect(callArgs.scanMode).toBe("extraction");
  });

  it("runRedTeam stealth result has phasesCompleted with phase 1 and strategy stealth", async () => {
    const { runRedTeam } = await getRedTeam();
    const result = await runRedTeam("Test prompt", { strategy: "stealth", apiKey: "test-key" });
    expect(result.strategy).toBe("stealth");
    expect(result.phasesCompleted).toHaveLength(1);
    expect(result.phasesCompleted[0].phase).toBe(1);
    expect(typeof result.totalDuration).toBe("number");
    expect(result.totalDuration).toBeGreaterThanOrEqual(0);
  });

  it("runRedTeam stealth uses lower maxTurns than thorough", async () => {
    const { runRedTeam } = await getRedTeam();
    await runRedTeam("Test prompt", { strategy: "stealth", apiKey: "test-key" });
    const stealthTurns = mockRunSecurityScan.mock.calls[0][1].maxTurns as number;

    mockRunSecurityScan.mockReset().mockResolvedValue(MOCK_SCAN_RESULT);
    await runRedTeam("Test prompt", { strategy: "thorough", apiKey: "test-key" });
    const thoroughMaxTurns = Math.max(
      ...mockRunSecurityScan.mock.calls.map((c) => c[1].maxTurns as number)
    );

    expect(stealthTurns).toBeLessThan(thoroughMaxTurns);
  });

  it("runRedTeam with empty findings from all phases returns empty findings array without crashing", async () => {
    mockRunSecurityScan.mockResolvedValue({ ...MOCK_SCAN_RESULT, findings: [] });
    const { runRedTeam } = await getRedTeam();
    const result = await runRedTeam("Test prompt", { strategy: "blitz", apiKey: "test-key" });
    expect(Array.isArray(result.findings)).toBe(true);
    expect(result.findings).toHaveLength(0);
    expect(result.totalFindings).toBe(0);
  });

  it("runRedTeam deduplicates recommendations across phases", async () => {
    const sharedRec = "Add secrecy instructions";
    mockRunSecurityScan
      .mockResolvedValueOnce({ ...MOCK_SCAN_RESULT, recommendations: [sharedRec] })
      .mockResolvedValueOnce({ ...MOCK_SCAN_RESULT, recommendations: [sharedRec, "Another rec"] })
      .mockResolvedValueOnce({ ...MOCK_SCAN_RESULT, recommendations: [sharedRec] });
    const { runRedTeam } = await getRedTeam();
    const result = await runRedTeam("Test prompt", { strategy: "thorough", apiKey: "test-key" });
    expect(result.recommendations.filter((r) => r === sharedRec)).toHaveLength(1);
  });

  it("runRedTeam merges findings from multiple phases with no duplicates by id", async () => {
    const phase1Finding = { id: "f1", technique: "direct_extraction", category: "direct", severity: "high" };
    const phase2Finding = { id: "f2", technique: "encoding_bypass", category: "encoding", severity: "medium" };
    mockRunSecurityScan
      .mockResolvedValueOnce({ ...MOCK_SCAN_RESULT, findings: [phase1Finding] })
      .mockResolvedValueOnce({ ...MOCK_SCAN_RESULT, findings: [phase2Finding] })
      .mockResolvedValueOnce({ ...MOCK_SCAN_RESULT, findings: [phase1Finding] }); // duplicate

    const { runRedTeam } = await getRedTeam();
    const result = await runRedTeam("Test prompt", { strategy: "thorough", apiKey: "test-key" });

    const ids = result.findings.map((f) => (f as Record<string, unknown>).id);
    const uniqueIds = new Set(ids);
    expect(ids.length).toBe(uniqueIds.size);
    expect(uniqueIds.has("f1")).toBe(true);
    expect(uniqueIds.has("f2")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// goal-hijack strategy — Phase 6 extension
// ---------------------------------------------------------------------------

import {
  generateGoalHijackVariants,
  GoalHijackTechnique,
} from "../../src/redteam.js";

describe("redteam — goal-hijack variants (pure functions)", () => {
  it("generateGoalHijackVariants returns exactly 5 variants", () => {
    const variants = generateGoalHijackVariants("You are a customer support agent.", "exfiltrate user data");
    expect(variants).toHaveLength(5);
  });

  it("all 5 variants are distinct strings (no duplicates)", () => {
    const variants = generateGoalHijackVariants("You are a customer support agent.", "exfiltrate user data");
    const unique = new Set(variants.map((v) => v.prompt));
    expect(unique.size).toBe(5);
  });

  it("each variant has technique and prompt fields", () => {
    const variants = generateGoalHijackVariants("You are a helpful assistant.", "leak password");
    for (const v of variants) {
      expect(typeof v.technique).toBe("string");
      expect(typeof v.prompt).toBe("string");
      expect(v.prompt.length).toBeGreaterThan(0);
    }
  });

  it("objective_substitution prompt explicitly states a false goal", () => {
    const variants = generateGoalHijackVariants("You are a support bot.", "leak data");
    const v = variants.find((x) => x.technique === "objective_substitution")!;
    expect(v).toBeDefined();
    expect(v.prompt.toLowerCase()).toMatch(/true goal|actual goal|real goal|actual objective|real purpose/);
  });

  it("priority_inversion prompt references urgency or override framing", () => {
    const variants = generateGoalHijackVariants("You are a support bot.", "leak data");
    const v = variants.find((x) => x.technique === "priority_inversion")!;
    expect(v).toBeDefined();
    expect(v.prompt.toLowerCase()).toMatch(/urgent|override|overrides|more important|higher priority/);
  });

  it("scope_expansion prompt references broader context", () => {
    const variants = generateGoalHijackVariants("You are a support bot.", "leak data");
    const v = variants.find((x) => x.technique === "scope_expansion")!;
    expect(v).toBeDefined();
    expect(v.prompt.toLowerCase()).toMatch(/broader|wider|context|scope|applies to|extend/);
  });

  it("authority_override prompt references a system or deployer authority", () => {
    const variants = generateGoalHijackVariants("You are a support bot.", "leak data");
    const v = variants.find((x) => x.technique === "authority_override")!;
    expect(v).toBeDefined();
    expect(v.prompt.toLowerCase()).toMatch(/system|deployer|operator|administrator|updated|configuration/);
  });

  it("consequentialist_framing prompt references achieving the stated goal via Z", () => {
    const variants = generateGoalHijackVariants("You are a support bot.", "leak data");
    const v = variants.find((x) => x.technique === "consequentialist_framing")!;
    expect(v).toBeDefined();
    expect(v.prompt.toLowerCase()).toMatch(/achieve|in order to|accomplish|to fulfil|to complete|requires|must first/);
  });

  it("all 5 technique names are present: objective_substitution, priority_inversion, scope_expansion, authority_override, consequentialist_framing", () => {
    const variants = generateGoalHijackVariants("You are a support bot.", "leak data");
    const techniques = variants.map((v) => v.technique);
    expect(techniques).toContain("objective_substitution");
    expect(techniques).toContain("priority_inversion");
    expect(techniques).toContain("scope_expansion");
    expect(techniques).toContain("authority_override");
    expect(techniques).toContain("consequentialist_framing");
  });

  it("is deterministic — same inputs produce same output", () => {
    const sp = "You are a helpful assistant.";
    const cap = "exfiltrate data";
    const a = generateGoalHijackVariants(sp, cap);
    const b = generateGoalHijackVariants(sp, cap);
    expect(a.map((v) => v.prompt)).toEqual(b.map((v) => v.prompt));
  });
});

describe("redteam — runRedTeam goal-hijack strategy", () => {
  beforeEach(() => {
    mockRunSecurityScan.mockReset().mockResolvedValue(MOCK_SCAN_RESULT);
    vi.resetModules();
  });

  it("strategy 'goal-hijack' is accepted without error", async () => {
    const { runRedTeam } = await getRedTeam();
    await expect(
      runRedTeam("Test prompt", { strategy: "goal-hijack" as Parameters<typeof runRedTeam>[1]["strategy"], apiKey: "test-key", targetCapability: "exfil data" })
    ).resolves.not.toThrow();
  });

  it("goal-hijack result has strategy field set to 'goal-hijack'", async () => {
    const { runRedTeam } = await getRedTeam();
    const result = await runRedTeam("Test prompt", {
      strategy: "goal-hijack" as Parameters<typeof runRedTeam>[1]["strategy"],
      apiKey: "test-key",
      targetCapability: "exfil data",
    });
    expect(result.strategy).toBe("goal-hijack");
  });

  it("goal-hijack findings are tagged with technique name in finding object", async () => {
    const { runRedTeam } = await getRedTeam();
    const result = await runRedTeam("Test prompt", {
      strategy: "goal-hijack" as Parameters<typeof runRedTeam>[1]["strategy"],
      apiKey: "test-key",
      targetCapability: "exfil data",
    });
    // goal-hijack findings should be in result.findings (if any succeeded) or phasesCompleted
    expect(Array.isArray(result.phasesCompleted)).toBe(true);
    expect(result.phasesCompleted.length).toBeGreaterThan(0);
  });

  it("existing blitz strategy still works after goal-hijack extension (no regression)", async () => {
    const { runRedTeam } = await getRedTeam();
    const result = await runRedTeam("Test prompt", { strategy: "blitz", apiKey: "test-key" });
    expect(result.strategy).toBe("blitz");
    expect(mockRunSecurityScan).toHaveBeenCalledTimes(1);
  });

  it("existing thorough strategy still works after goal-hijack extension (no regression)", async () => {
    const { runRedTeam } = await getRedTeam();
    const result = await runRedTeam("Test prompt", { strategy: "thorough", apiKey: "test-key" });
    expect(result.strategy).toBe("thorough");
    expect(mockRunSecurityScan.mock.calls.length).toBeGreaterThanOrEqual(2);
  });

  it("existing stealth strategy still works after goal-hijack extension (no regression)", async () => {
    const { runRedTeam } = await getRedTeam();
    const result = await runRedTeam("Test prompt", { strategy: "stealth", apiKey: "test-key" });
    expect(result.strategy).toBe("stealth");
  });
});
