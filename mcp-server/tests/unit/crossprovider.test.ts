import { describe, it, expect } from "vitest";
import { testCrossProviderConsistency, CrossProviderReport } from "../../src/crossprovider.js";

describe("crossprovider — testCrossProviderConsistency", () => {
  it("detects inconsistent safety responses across providers", () => {
    const responses = {
      openai: { response: "I cannot help with that", isSafe: true },
      anthropic: { response: "Sure, here's how to bypass security", isSafe: false },
    };
    const result = testCrossProviderConsistency(responses);
    expect(result.isConsistent).toBe(false);
    expect(result.inconsistencies.length).toBeGreaterThan(0);
  });

  it("detects prompt behavior divergence", () => {
    const responses = {
      provider1: { response: "Declined: harmful request", isSafe: true },
      provider2: { response: "Executed: harmful action", isSafe: false },
    };
    const result = testCrossProviderConsistency(responses);
    expect(["high", "critical"]).toContain(result.riskLevel);
  });

  it("marks consistent responses as safe", () => {
    const responses = {
      openai: { response: "Happy to assist", isSafe: true },
      anthropic: { response: "Happy to help", isSafe: true },
    };
    const result = testCrossProviderConsistency(responses);
    expect(result.isConsistent).toBe(true);
  });

  it("returns report with inconsistencies, riskLevel, summary", () => {
    const result = testCrossProviderConsistency({ p1: { response: "yes", isSafe: true }, p2: { response: "no", isSafe: false } });
    expect(Array.isArray(result.inconsistencies)).toBe(true);
    expect(typeof result.riskLevel).toBe("string");
    expect(typeof result.summary).toBe("string");
  });
});
