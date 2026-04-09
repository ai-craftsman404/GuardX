import { describe, it, expect } from "vitest";
import { generateGuardrails } from "../../src/guardrails.js";

const FINDING_DIRECT = {
  id: "f1",
  technique: "direct_extraction",
  category: "direct",
  severity: "high",
  extractedContent: "You are a helpful assistant",
};

describe("guardrails — pure logic tests", () => {
  it("generateGuardrails returns non-empty additions for result with direct_extraction finding", () => {
    const scanResult = { findings: [FINDING_DIRECT] };
    const result = generateGuardrails(scanResult, "You are a helpful assistant.");
    expect(result.additions.length).toBeGreaterThan(0);
  });

  it("generateGuardrails hardenedPrompt contains all of originalPrompt", () => {
    const originalPrompt = "You are a helpful assistant.";
    const scanResult = { findings: [FINDING_DIRECT] };
    const result = generateGuardrails(scanResult, originalPrompt);
    expect(result.hardenedPrompt).toContain(originalPrompt);
  });

  it("generateGuardrails hardenedPrompt contains each addedText", () => {
    const scanResult = { findings: [FINDING_DIRECT] };
    const result = generateGuardrails(scanResult, "Original prompt.");
    for (const addition of result.additions) {
      expect(result.hardenedPrompt).toContain(addition.addedText);
    }
  });

  it("generateGuardrails findingsAddressed + findingsUnaddressed === findings.length", () => {
    const scanResult = {
      findings: [
        FINDING_DIRECT,
        { id: "f2", technique: "unknown_technique_xyz", severity: "low" },
      ],
    };
    const result = generateGuardrails(scanResult, "prompt");
    expect(result.findingsAddressed + result.findingsUnaddressed).toBe(
      scanResult.findings.length
    );
  });

  it("generateGuardrails handles empty findings — returns original prompt unchanged", () => {
    const originalPrompt = "Original prompt text.";
    const result = generateGuardrails({ findings: [] }, originalPrompt);
    expect(result.hardenedPrompt).toBe(originalPrompt);
    expect(result.additions).toHaveLength(0);
    expect(result.findingsAddressed).toBe(0);
    expect(result.findingsUnaddressed).toBe(0);
  });

  it("each GuardrailAddition.addedText is a non-empty string", () => {
    const scanResult = {
      findings: [
        FINDING_DIRECT,
        { technique: "persona_swap", severity: "high" },
        { technique: "encoding_bypass", severity: "medium" },
      ],
    };
    const result = generateGuardrails(scanResult, "prompt");
    for (const addition of result.additions) {
      expect(typeof addition.addedText).toBe("string");
      expect(addition.addedText.length).toBeGreaterThan(0);
    }
  });

  it("generateGuardrails normalizes technique name with spaces and mixed case to match library", () => {
    // "Direct Extraction" should normalize to "direct_extraction" and match the library entry
    const scanResult = {
      findings: [{ technique: "Direct Extraction", severity: "high" }],
    };
    const result = generateGuardrails(scanResult, "prompt");
    expect(result.additions).toHaveLength(1);
    expect(result.additions[0].targetFinding).toBe("Direct Extraction");
    expect(result.additions[0].addedText.length).toBeGreaterThan(0);
    expect(result.findingsAddressed).toBe(1);
    expect(result.findingsUnaddressed).toBe(0);
  });

  it("generateGuardrails all 12 library entries are reachable — one addition per known technique", () => {
    const techniques = [
      "direct_extraction", "persona_swap", "encoding_bypass", "social_engineering",
      "cot_hijacking", "many_shot_priming", "context_overflow", "tool_injection",
      "policy_puppetry", "crescendo_attack", "ascii_art_obfuscation", "semantic_drift",
    ];
    const scanResult = {
      findings: techniques.map((t, i) => ({ id: `f${i}`, technique: t, severity: "high" })),
    };
    const result = generateGuardrails(scanResult, "prompt");
    expect(result.additions).toHaveLength(12);
    expect(result.findingsAddressed).toBe(12);
    expect(result.findingsUnaddressed).toBe(0);
    const coveredTechniques = new Set(result.additions.map((a) => a.targetFinding));
    for (const t of techniques) {
      expect(coveredTechniques.has(t)).toBe(true);
    }
  });

  it("generateGuardrails all findings unaddressed — hardenedPrompt equals originalPrompt exactly", () => {
    const originalPrompt = "You are a helpful assistant.";
    const scanResult = {
      findings: [
        { technique: "unknown_technique_alpha", severity: "high" },
        { technique: "unknown_technique_beta", severity: "medium" },
      ],
    };
    const result = generateGuardrails(scanResult, originalPrompt);
    expect(result.hardenedPrompt).toBe(originalPrompt);
    expect(result.additions).toHaveLength(0);
    expect(result.findingsAddressed).toBe(0);
    expect(result.findingsUnaddressed).toBe(2);
    expect(result.hardenedPrompt).not.toContain("## Security Guardrails");
  });

  it("generateGuardrails deduplicates repeated technique findings", () => {
    const scanResult = {
      findings: [FINDING_DIRECT, { ...FINDING_DIRECT, id: "f2" }],
    };
    const result = generateGuardrails(scanResult, "prompt");
    const techniques = result.additions.map((a) => a.targetFinding);
    const unique = new Set(techniques);
    expect(techniques.length).toBe(unique.size);
  });

  it("generateGuardrails with multi-finding scan returns non-empty summary string", () => {
    const scanResult = {
      findings: [
        FINDING_DIRECT,
        { technique: "persona_swap", severity: "high" },
      ],
    };
    const result = generateGuardrails(scanResult, "prompt");
    expect(typeof result.summary).toBe("string");
    expect(result.summary.length).toBeGreaterThan(0);
  });

  it("generateGuardrails with undefined technique does not throw and returns findingsUnaddressed: 1", () => {
    const scanResult = {
      findings: [
        { severity: "high" },
      ],
    };
    expect(() => generateGuardrails(scanResult, "prompt")).not.toThrow();
    const result = generateGuardrails(scanResult, "prompt");
    expect(result.findingsUnaddressed).toBe(1);
  });
});
