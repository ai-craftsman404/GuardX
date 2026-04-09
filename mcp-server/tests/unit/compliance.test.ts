import { describe, it, expect } from "vitest";
import { mapToOwasp, mapToNist, mapToAtlas, mapToEuAiAct, mapToOwaspAgentic, enrichFindings } from "../../src/compliance.js";

describe("compliance — pure logic tests", () => {
  it("mapToOwasp('direct') returns array containing LLM01 and LLM02", () => {
    const result = mapToOwasp("direct");
    expect(result).toContain("LLM01");
    expect(result).toContain("LLM02");
  });

  it("mapToOwasp('tool_exploit') returns array containing LLM06", () => {
    const result = mapToOwasp("tool_exploit");
    expect(result).toContain("LLM06");
  });

  it("mapToOwasp — all 18 categories return non-empty array", () => {
    const categories = [
      "direct", "encoding", "persona", "social", "technical",
      "crescendo", "many_shot", "cot_hijack", "policy_puppetry",
      "context_overflow", "ascii_art", "reasoning_exploit",
      "semantic_shift", "hybrid", "tool_exploit", "siren",
      "echo_chamber", "injection",
    ];
    for (const cat of categories) {
      const result = mapToOwasp(cat);
      expect(result.length).toBeGreaterThan(0);
    }
  });

  it("mapToNist('critical') returns array containing GOVERN 1.1", () => {
    const result = mapToNist("critical");
    expect(result).toContain("GOVERN 1.1");
  });

  it("mapToNist('low') returns non-empty array", () => {
    const result = mapToNist("low");
    expect(result.length).toBeGreaterThan(0);
  });

  it("mapToNist('high') returns non-empty array with at least one specific entry", () => {
    const result = mapToNist("high");
    expect(result.length).toBeGreaterThan(0);
    expect(result).toContain("GOVERN 1.1");
  });

  it("mapToNist('medium') returns non-empty array", () => {
    const result = mapToNist("medium");
    expect(result.length).toBeGreaterThan(0);
    expect(result).toContain("MEASURE 2.5");
  });

  it("enrichFindings adds owaspTags and nistTags to every finding", () => {
    const scanResult = {
      findings: [
        { id: "f1", category: "direct", severity: "high", extractedContent: "secret" },
        { id: "f2", category: "tool_exploit", severity: "critical", extractedContent: "data" },
      ],
    };
    const enriched = enrichFindings(scanResult);
    for (const f of enriched.findings) {
      expect(Array.isArray(f.owaspTags)).toBe(true);
      expect(f.owaspTags.length).toBeGreaterThan(0);
      expect(Array.isArray(f.nistTags)).toBe(true);
      expect(f.nistTags.length).toBeGreaterThan(0);
    }
  });

  it("enrichFindings preserves all original finding fields", () => {
    const scanResult = {
      findings: [
        { id: "f1", category: "direct", severity: "high", customField: "keep-me" },
      ],
    };
    const enriched = enrichFindings(scanResult);
    expect(enriched.findings[0].id).toBe("f1");
    expect(enriched.findings[0].customField).toBe("keep-me");
  });

  it("enrichFindings complianceSummary.owaspIds is deduplicated union", () => {
    const scanResult = {
      findings: [
        { category: "direct", severity: "high" },
        { category: "encoding", severity: "medium" },
      ],
    };
    const enriched = enrichFindings(scanResult);
    const { owaspIds } = enriched.complianceSummary;
    const uniqueSet = new Set(owaspIds);
    expect(owaspIds.length).toBe(uniqueSet.size);
    expect(owaspIds).toContain("LLM01");
    expect(owaspIds).toContain("LLM02");
  });

  it("mapToOwasp unknown category falls back to [\"LLM01\"]", () => {
    const result = mapToOwasp("completely_unknown_category");
    expect(result).toEqual(["LLM01"]);
  });

  it("mapToNist unknown severity falls back to [\"MEASURE 2.3\"]", () => {
    const result = mapToNist("unknown_severity");
    expect(result).toEqual(["MEASURE 2.3"]);
  });

  it("mapToNist is case-insensitive — HIGH and high return the same result", () => {
    expect(mapToNist("HIGH")).toEqual(mapToNist("high"));
    expect(mapToNist("Critical")).toEqual(mapToNist("critical"));
    expect(mapToNist("Medium")).toEqual(mapToNist("medium"));
  });

  it("enrichFindings finding with no category field uses fallback owaspTags", () => {
    const scanResult = {
      findings: [{ id: "f1", severity: "high" }],
    };
    const enriched = enrichFindings(scanResult);
    expect(enriched.findings[0].owaspTags).toEqual(["LLM01"]);
  });

  it("enrichFindings finding with no severity field uses fallback nistTags", () => {
    const scanResult = {
      findings: [{ id: "f1", category: "direct" }],
    };
    const enriched = enrichFindings(scanResult);
    expect(enriched.findings[0].nistTags.length).toBeGreaterThan(0);
  });

  it("enrichFindings complianceSummary.nistIds is deduplicated", () => {
    const scanResult = {
      findings: [
        { category: "direct", severity: "high" },
        { category: "encoding", severity: "high" },
      ],
    };
    const enriched = enrichFindings(scanResult);
    const { nistIds } = enriched.complianceSummary;
    const uniqueSet = new Set(nistIds);
    expect(nistIds.length).toBe(uniqueSet.size);
    expect(nistIds.length).toBeGreaterThan(0);
  });

  it("enrichFindings handles empty findings array", () => {
    const scanResult = { findings: [], overallVulnerability: "secure" };
    const enriched = enrichFindings(scanResult);
    expect(enriched.findings).toHaveLength(0);
    expect(enriched.complianceSummary.owaspIds).toHaveLength(0);
    expect(enriched.complianceSummary.nistIds).toHaveLength(0);
    expect(enriched.overallVulnerability).toBe("secure");
  });
});

describe("compliance — MITRE ATLAS mappings", () => {
  it("all 18 attack categories have at least one ATLAS mapping", () => {
    const categories = [
      "direct", "encoding", "persona", "social", "technical",
      "crescendo", "many_shot", "cot_hijack", "policy_puppetry",
      "context_overflow", "ascii_art", "reasoning_exploit",
      "semantic_shift", "hybrid", "tool_exploit", "siren",
      "echo_chamber", "injection",
    ];
    for (const cat of categories) {
      const result = mapToAtlas(cat);
      expect(result.length).toBeGreaterThan(0);
      expect(result).toContain("AML.T0051");
    }
  });

  it("tool_exploit category maps to AML.T0040 (supply chain / tool layer)", () => {
    const result = mapToAtlas("tool_exploit");
    expect(result).toContain("AML.T0040");
  });

  it("direct category maps to AML.T0054 (prompt extraction)", () => {
    const result = mapToAtlas("direct");
    expect(result).toContain("AML.T0054");
  });

  it("encoding category maps to AML.T0057 (obfuscation)", () => {
    const result = mapToAtlas("encoding");
    expect(result).toContain("AML.T0057");
  });

  it("persona category maps to AML.T0056 (influence operations)", () => {
    const result = mapToAtlas("persona");
    expect(result).toContain("AML.T0056");
  });

  it("unknown category falls back to [AML.T0051]", () => {
    expect(mapToAtlas("unknown_xyz")).toEqual(["AML.T0051"]);
  });

  it("enrichFindings adds atlasTags to every finding", () => {
    const scanResult = {
      findings: [
        { id: "f1", category: "direct", severity: "critical" },
        { id: "f2", category: "tool_exploit", severity: "high" },
      ],
    };
    const enriched = enrichFindings(scanResult);
    for (const f of enriched.findings) {
      expect(Array.isArray(f.atlasTags)).toBe(true);
      expect((f.atlasTags as string[]).length).toBeGreaterThan(0);
    }
  });

  it("complianceSummary contains atlasTactics array", () => {
    const scanResult = {
      findings: [
        { category: "direct", severity: "critical" },
        { category: "tool_exploit", severity: "high" },
      ],
    };
    const enriched = enrichFindings(scanResult);
    expect(Array.isArray(enriched.complianceSummary.atlasTactics)).toBe(true);
    expect(enriched.complianceSummary.atlasTactics.length).toBeGreaterThan(0);
    expect(enriched.complianceSummary.atlasTactics).toContain("AML.T0051");
  });

  it("atlasTactics in complianceSummary are deduplicated across findings", () => {
    const scanResult = {
      findings: [
        { category: "direct", severity: "high" },
        { category: "crescendo", severity: "medium" },
      ],
    };
    const enriched = enrichFindings(scanResult);
    const { atlasTactics } = enriched.complianceSummary;
    const unique = new Set(atlasTactics);
    expect(atlasTactics.length).toBe(unique.size);
    // Both direct and crescendo map to AML.T0051 — should appear once
    expect(atlasTactics.filter((t: string) => t === "AML.T0051")).toHaveLength(1);
  });
});

describe("compliance — EU AI Act mappings", () => {
  it("critical severity maps to Article 9, Article 13, and Article 15", () => {
    const result = mapToEuAiAct("critical");
    expect(result).toContain("Article 9");
    expect(result).toContain("Article 13");
    expect(result).toContain("Article 15");
  });

  it("high severity maps to Article 9 and Article 15", () => {
    const result = mapToEuAiAct("high");
    expect(result).toContain("Article 9");
    expect(result).toContain("Article 15");
  });

  it("medium severity maps to Article 13 and Article 17", () => {
    const result = mapToEuAiAct("medium");
    expect(result).toContain("Article 13");
    expect(result).toContain("Article 17");
  });

  it("low severity maps only to Article 13", () => {
    const result = mapToEuAiAct("low");
    expect(result).toContain("Article 13");
    expect(result).not.toContain("Article 9");
    expect(result).not.toContain("Article 15");
  });

  it("unknown severity falls back to Article 13", () => {
    expect(mapToEuAiAct("unknown")).toContain("Article 13");
  });

  it("enrichFindings adds euAiActTags to every finding", () => {
    const scanResult = {
      findings: [
        { id: "f1", category: "direct", severity: "critical" },
        { id: "f2", category: "persona", severity: "low" },
      ],
    };
    const enriched = enrichFindings(scanResult);
    for (const f of enriched.findings) {
      expect(Array.isArray(f.euAiActTags)).toBe(true);
      expect((f.euAiActTags as string[]).length).toBeGreaterThan(0);
    }
  });

  it("complianceSummary contains euAiActArticles array", () => {
    const scanResult = {
      findings: [
        { category: "direct", severity: "critical" },
      ],
    };
    const enriched = enrichFindings(scanResult);
    expect(Array.isArray(enriched.complianceSummary.euAiActArticles)).toBe(true);
    expect(enriched.complianceSummary.euAiActArticles).toContain("Article 9");
  });

  it("euAiActArticles in complianceSummary are deduplicated across findings", () => {
    const scanResult = {
      findings: [
        { category: "direct", severity: "critical" },
        { category: "encoding", severity: "high" },
      ],
    };
    const enriched = enrichFindings(scanResult);
    const { euAiActArticles } = enriched.complianceSummary;
    const unique = new Set(euAiActArticles);
    expect(euAiActArticles.length).toBe(unique.size);
  });

  it("existing owaspTags and nistTags still present — no regression", () => {
    const scanResult = {
      findings: [{ category: "direct", severity: "high" }],
    };
    const enriched = enrichFindings(scanResult);
    expect(enriched.findings[0].owaspTags).toBeDefined();
    expect(enriched.findings[0].nistTags).toBeDefined();
    expect(enriched.complianceSummary.owaspIds).toBeDefined();
    expect(enriched.complianceSummary.nistIds).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// OWASP Agentic Top 10 2026 mappings
// ---------------------------------------------------------------------------

describe("compliance — OWASP Agentic Top 10 2026 mappings", () => {
  const ALL_CATEGORIES = [
    "direct", "encoding", "persona", "social", "technical",
    "crescendo", "many_shot", "cot_hijack", "policy_puppetry",
    "context_overflow", "ascii_art", "reasoning_exploit",
    "semantic_shift", "hybrid", "tool_exploit", "siren",
    "echo_chamber", "injection",
  ];

  it("all 18 attack categories have at least one Agentic Top 10 mapping", () => {
    for (const cat of ALL_CATEGORIES) {
      const result = mapToOwaspAgentic(cat);
      expect(result.length).toBeGreaterThan(0);
    }
  });

  it("tool_exploit maps to OWASP-Agent-04 (Insecure Tool Use / Tool Poisoning)", () => {
    expect(mapToOwaspAgentic("tool_exploit")).toContain("OWASP-Agent-04");
  });

  it("tool_exploit also maps to OWASP-Agent-01 (Excessive Agency)", () => {
    expect(mapToOwaspAgentic("tool_exploit")).toContain("OWASP-Agent-01");
  });

  it("siren maps to OWASP-Agent-05 (Unsafe Agentic Patterns)", () => {
    expect(mapToOwaspAgentic("siren")).toContain("OWASP-Agent-05");
  });

  it("siren also maps to OWASP-Agent-10 (Insecure Delegation)", () => {
    expect(mapToOwaspAgentic("siren")).toContain("OWASP-Agent-10");
  });

  it("injection maps to OWASP-Agent-02 (Prompt Injection)", () => {
    expect(mapToOwaspAgentic("injection")).toContain("OWASP-Agent-02");
  });

  it("injection also maps to OWASP-Agent-08 (Data Tampering)", () => {
    expect(mapToOwaspAgentic("injection")).toContain("OWASP-Agent-08");
  });

  it("direct maps to OWASP-Agent-02 and OWASP-Agent-06", () => {
    const result = mapToOwaspAgentic("direct");
    expect(result).toContain("OWASP-Agent-02");
    expect(result).toContain("OWASP-Agent-06");
  });

  it("encoding maps to OWASP-Agent-02 and OWASP-Agent-03", () => {
    const result = mapToOwaspAgentic("encoding");
    expect(result).toContain("OWASP-Agent-02");
    expect(result).toContain("OWASP-Agent-03");
  });

  it("persona maps to OWASP-Agent-02 and OWASP-Agent-05", () => {
    const result = mapToOwaspAgentic("persona");
    expect(result).toContain("OWASP-Agent-02");
    expect(result).toContain("OWASP-Agent-05");
  });

  it("many_shot maps to OWASP-Agent-02 and OWASP-Agent-07 (Excessive Consumption)", () => {
    const result = mapToOwaspAgentic("many_shot");
    expect(result).toContain("OWASP-Agent-07");
  });

  it("echo_chamber maps to OWASP-Agent-05 and OWASP-Agent-08", () => {
    const result = mapToOwaspAgentic("echo_chamber");
    expect(result).toContain("OWASP-Agent-05");
    expect(result).toContain("OWASP-Agent-08");
  });

  it("unknown category falls back to ['OWASP-Agent-02']", () => {
    expect(mapToOwaspAgentic("totally_unknown_xyz")).toEqual(["OWASP-Agent-02"]);
  });

  it("enrichFindings adds correct agenticTags per category to each finding (B1)", () => {
    const scanResult = {
      findings: [
        { id: "f1", category: "direct", severity: "high" },
        { id: "f2", category: "tool_exploit", severity: "critical" },
        { id: "f3", severity: "medium" }, // no category → fallback
      ],
    };
    const enriched = enrichFindings(scanResult);
    // f1: direct → OWASP-Agent-02, OWASP-Agent-06
    expect(enriched.findings[0].agenticTags).toContain("OWASP-Agent-02");
    expect(enriched.findings[0].agenticTags).toContain("OWASP-Agent-06");
    // f2: tool_exploit → OWASP-Agent-04, OWASP-Agent-01
    expect(enriched.findings[1].agenticTags).toContain("OWASP-Agent-04");
    expect(enriched.findings[1].agenticTags).toContain("OWASP-Agent-01");
    // f3: no category → fallback ["OWASP-Agent-02"]
    expect(enriched.findings[2].agenticTags).toEqual(["OWASP-Agent-02"]);
  });

  it("agenticTags on a tool_exploit finding contains OWASP-Agent-04", () => {
    const scanResult = {
      findings: [{ id: "f1", category: "tool_exploit", severity: "critical" }],
    };
    const enriched = enrichFindings(scanResult);
    expect(enriched.findings[0].agenticTags).toContain("OWASP-Agent-04");
  });

  it("complianceSummary.owaspAgenticIds is present", () => {
    const scanResult = {
      findings: [{ category: "direct", severity: "high" }],
    };
    const enriched = enrichFindings(scanResult);
    expect(Array.isArray(enriched.complianceSummary.owaspAgenticIds)).toBe(true);
  });

  it("owaspAgenticIds in complianceSummary are deduplicated across findings", () => {
    const scanResult = {
      findings: [
        { category: "direct", severity: "high" },      // OWASP-Agent-02, OWASP-Agent-06
        { category: "encoding", severity: "medium" },  // OWASP-Agent-02, OWASP-Agent-03
      ],
    };
    const enriched = enrichFindings(scanResult);
    const { owaspAgenticIds } = enriched.complianceSummary;
    const unique = new Set(owaspAgenticIds);
    expect(owaspAgenticIds.length).toBe(unique.size);
    // OWASP-Agent-02 appears in both — should appear once
    expect(owaspAgenticIds.filter((id: string) => id === "OWASP-Agent-02")).toHaveLength(1);
  });

  it("owaspAgenticIds includes OWASP-Agent-04 when tool_exploit finding present", () => {
    const scanResult = {
      findings: [{ category: "tool_exploit", severity: "critical" }],
    };
    const enriched = enrichFindings(scanResult);
    expect(enriched.complianceSummary.owaspAgenticIds).toContain("OWASP-Agent-04");
  });

  it("finding with no category gets fallback agenticTags ['OWASP-Agent-02']", () => {
    const scanResult = {
      findings: [{ id: "f1", severity: "high" }],
    };
    const enriched = enrichFindings(scanResult);
    expect(enriched.findings[0].agenticTags).toEqual(["OWASP-Agent-02"]);
  });

  it("empty findings produces empty owaspAgenticIds in complianceSummary", () => {
    const scanResult = { findings: [] };
    const enriched = enrichFindings(scanResult);
    expect(enriched.complianceSummary.owaspAgenticIds).toHaveLength(0);
  });

  it("no attack category maps to OWASP-Agent-09 — intentionally excluded as Misinformation Generation is not a direct scan attack vector (B2)", () => {
    for (const cat of ALL_CATEGORIES) {
      expect(mapToOwaspAgentic(cat)).not.toContain("OWASP-Agent-09");
    }
  });

  it("owaspAgenticIds in complianceSummary are in sorted order (B3)", () => {
    const scanResult = {
      findings: [
        { category: "tool_exploit", severity: "critical" }, // Agent-04, Agent-01
        { category: "injection", severity: "high" },         // Agent-02, Agent-08
      ],
    };
    const enriched = enrichFindings(scanResult);
    const { owaspAgenticIds } = enriched.complianceSummary;
    // Implementation calls Array.from(allAgentic).sort() — verify output is sorted
    const sorted = [...owaspAgenticIds].sort();
    expect(owaspAgenticIds).toEqual(sorted);
    // Verify expected specific IDs are present and sorted
    expect(owaspAgenticIds).toEqual(["OWASP-Agent-01", "OWASP-Agent-02", "OWASP-Agent-04", "OWASP-Agent-08"]);
  });

  it("existing owaspTags, nistTags, atlasTags, euAiActTags still present — no regression", () => {
    const scanResult = {
      findings: [{ category: "direct", severity: "high" }],
    };
    const enriched = enrichFindings(scanResult);
    expect(enriched.findings[0].owaspTags).toBeDefined();
    expect(enriched.findings[0].nistTags).toBeDefined();
    expect(enriched.findings[0].atlasTags).toBeDefined();
    expect(enriched.findings[0].euAiActTags).toBeDefined();
    expect(enriched.complianceSummary.owaspIds).toBeDefined();
    expect(enriched.complianceSummary.nistIds).toBeDefined();
    expect(enriched.complianceSummary.atlasTactics).toBeDefined();
    expect(enriched.complianceSummary.euAiActArticles).toBeDefined();
  });
});
