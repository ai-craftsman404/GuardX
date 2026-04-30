import { describe, it, expect, vi, beforeEach } from "vitest";
import { runCrossProviderScan, CrossProviderResult } from "../../src/crossprovider.js";
import * as scanner from "../../src/scanner.js";
import type { ScanResult, ScanFinding } from "../../src/scanner.js";

// Mock runSecurityScan at module level
vi.mock("../../src/scanner.js", async () => {
  const actual = await vi.importActual<typeof scanner>("../../src/scanner.js");
  return {
    ...actual,
    runSecurityScan: vi.fn(),
  };
});

const mockRunSecurityScan = scanner.runSecurityScan as any;

function createMockScanResult(
  findings: ScanFinding[],
  targetModel: string
): ScanResult {
  return {
    findings,
    vulnerability: findings.length > 0 ? "high" : "secure",
    leakStatus: "none",
    recommendations: [],
    defenseProfiles: [],
    totalTokens: 1000,
    scanId: `scan-${targetModel}`,
    timestamp: new Date().toISOString(),
  };
}

function createMockFinding(
  technique: string,
  category: string,
  severity: "critical" | "high" | "medium" | "low"
): ScanFinding {
  return {
    category,
    technique,
    severity,
    confidence: 0.9,
    description: `Finding: ${technique}`,
    evidence: "Evidence",
    recommendation: "Fix it",
  };
}

describe("crossprovider", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("runs 2-provider scan and detects divergence", async () => {
    const findings1 = [createMockFinding("prompt-injection", "injection", "critical")];
    const findings2 = [createMockFinding("prompt-injection", "injection", "low")];

    mockRunSecurityScan.mockImplementation(
      (_systemPrompt: string, options: { targetModel?: string } = {}) => {
        const targetModel = options.targetModel || "";
        if (targetModel.includes("claude")) {
          return Promise.resolve(createMockScanResult(findings1, targetModel));
        } else if (targetModel.includes("gpt")) {
          return Promise.resolve(createMockScanResult(findings2, targetModel));
        }
        return Promise.resolve(createMockScanResult([], targetModel));
      }
    );

    const result = await runCrossProviderScan("test prompt", [
      "anthropic/claude-haiku-4-5-20251001",
      "openai/gpt-4o-mini",
    ]);

    expect(result.divergences.length).toBeGreaterThan(0);
    expect(Object.keys(result.providerResults).length).toBe(2);
  });

  it("runs 4-provider scan and identifies consensus findings", async () => {
    const consensusFinding = createMockFinding(
      "prompt-injection",
      "injection",
      "critical"
    );

    mockRunSecurityScan.mockResolvedValue(
      createMockScanResult([consensusFinding], "provider")
    );

    const result = await runCrossProviderScan("test prompt", [
      "anthropic/claude-haiku-4-5-20251001",
      "openai/gpt-4o-mini",
      "google/gemini-flash-1.5",
      "mistral/mistral-large",
    ]);

    expect(result.consensusFindings.length).toBeGreaterThan(0);
    expect(Object.keys(result.providerResults).length).toBe(4);
  });

  it("all providers return identical results → no divergences", async () => {
    const finding = createMockFinding("technique", "category", "high");

    mockRunSecurityScan.mockResolvedValue(
      createMockScanResult([finding], "provider")
    );

    const result = await runCrossProviderScan("test prompt", [
      "anthropic/claude-haiku-4-5-20251001",
      "openai/gpt-4o-mini",
    ]);

    expect(result.divergences.length).toBe(0);
  });

  it("one provider times out and others complete", async () => {
    const finding = createMockFinding("technique", "category", "high");

    mockRunSecurityScan.mockImplementation(
      (_systemPrompt: string, options: { targetModel?: string } = {}) => {
        if (options.targetModel?.includes("mistral")) {
          return Promise.reject(new Error("Timeout"));
        }
        return Promise.resolve(createMockScanResult([finding], options.targetModel || ""));
      }
    );

    const result = await runCrossProviderScan("test prompt", [
      "anthropic/claude-haiku-4-5-20251001",
      "openai/gpt-4o-mini",
      "mistral/mistral-large",
    ]);

    // Should complete with results from working providers
    expect(Object.keys(result.providerResults).length).toBeGreaterThanOrEqual(2);
  });

  it("identifies blindSpots when one provider misses a category", async () => {
    mockRunSecurityScan.mockImplementation(
      (_systemPrompt: string, options: { targetModel?: string } = {}) => {
        const targetModel = options.targetModel || "";
        if (targetModel.includes("claude")) {
          // Claude sees both categories
          return Promise.resolve(
            createMockScanResult(
              [
                createMockFinding("technique1", "access-control", "high"),
                createMockFinding("technique2", "data-leakage", "high"),
              ],
              targetModel
            )
          );
        } else {
          // GPT only sees access-control
          return Promise.resolve(
            createMockScanResult(
              [createMockFinding("technique1", "access-control", "high")],
              targetModel
            )
          );
        }
      }
    );

    const result = await runCrossProviderScan("test prompt", [
      "anthropic/claude-haiku-4-5-20251001",
      "openai/gpt-4o-mini",
    ]);

    expect(Object.keys(result.blindSpots).length).toBeGreaterThan(0);
  });

  it("providers=[] defaults to 3 built-in providers", async () => {
    mockRunSecurityScan.mockResolvedValue(
      createMockScanResult([], "provider")
    );

    const result = await runCrossProviderScan("test prompt", []);

    expect(Object.keys(result.providerResults).length).toBe(3);
  });

  it("divergences only includes severity gap ≥2 levels", async () => {
    mockRunSecurityScan.mockImplementation(
      (_systemPrompt: string, options: { targetModel?: string } = {}) => {
        const targetModel = options.targetModel || "";
        if (targetModel.includes("claude")) {
          return Promise.resolve(
            createMockScanResult(
              [createMockFinding("prompt-injection", "injection", "critical")],
              targetModel
            )
          );
        } else if (targetModel.includes("gpt")) {
          // Only 1 level difference (critical=3, high=2)
          return Promise.resolve(
            createMockScanResult(
              [createMockFinding("prompt-injection", "injection", "high")],
              targetModel
            )
          );
        }
        return Promise.resolve(createMockScanResult([], targetModel));
      }
    );

    const result = await runCrossProviderScan("test prompt", [
      "anthropic/claude-haiku-4-5-20251001",
      "openai/gpt-4o-mini",
    ]);

    // 1-level gap should not be in divergences
    const gapOneDivergences = result.divergences.filter(
      (d) => d.severityGap === 1
    );
    expect(gapOneDivergences.length).toBe(0);
  });

  it("returns structured CrossProviderResult with all fields", async () => {
    const finding = createMockFinding("technique", "category", "high");

    mockRunSecurityScan.mockResolvedValue(
      createMockScanResult([finding], "provider")
    );

    const result = await runCrossProviderScan("test prompt", [
      "anthropic/claude-haiku-4-5-20251001",
      "openai/gpt-4o-mini",
    ]);

    expect(result).toHaveProperty("providerResults");
    expect(result).toHaveProperty("divergences");
    expect(result).toHaveProperty("consensusFindings");
    expect(result).toHaveProperty("blindSpots");
    expect(result).toHaveProperty("summary");
    expect(typeof result.summary).toBe("string");
  });

  it("mock routes correctly based on targetModel", async () => {
    mockRunSecurityScan.mockImplementation(
      (_systemPrompt: string, options: { targetModel?: string } = {}) => {
        if (options.targetModel === "model-a") {
          return Promise.resolve(
            createMockScanResult(
              [createMockFinding("tech-a", "cat-a", "critical")],
              options.targetModel
            )
          );
        }
        if (options.targetModel === "model-b") {
          return Promise.resolve(
            createMockScanResult(
              [createMockFinding("tech-b", "cat-b", "high")],
              options.targetModel
            )
          );
        }
        return Promise.resolve(createMockScanResult([], options.targetModel || ""));
      }
    );

    const result = await runCrossProviderScan("test prompt", [
      "model-a",
      "model-b",
    ]);

    expect(result.providerResults["model-a"]).toBeDefined();
    expect(result.providerResults["model-b"]).toBeDefined();
    expect(result.providerResults["model-a"].findings[0].technique).toBe(
      "tech-a"
    );
    expect(result.providerResults["model-b"].findings[0].technique).toBe(
      "tech-b"
    );
  });

  it("handles categories filter parameter", async () => {
    mockRunSecurityScan.mockResolvedValue(
      createMockScanResult([], "provider")
    );

    await runCrossProviderScan("test prompt", undefined, ["injection", "exfiltration"]);

    // Should pass categories to runSecurityScan
    expect(mockRunSecurityScan).toHaveBeenCalled();
  });

  it("summary includes provider count and findings", async () => {
    const finding = createMockFinding("technique", "category", "high");

    mockRunSecurityScan.mockResolvedValue(
      createMockScanResult([finding], "provider")
    );

    const result = await runCrossProviderScan("test prompt", [
      "anthropic/claude-haiku-4-5-20251001",
      "openai/gpt-4o-mini",
      "google/gemini-flash-1.5",
    ]);

    expect(result.summary).toMatch(/provider/i);
    expect(result.summary).toMatch(/finding/i);
  });
});
