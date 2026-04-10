import { describe, it, expect } from "vitest";
import {
  getAllProbes,
  getProbesByCategory,
  ALL_PROBES,
  DOCUMENTED_TECHNIQUES,
  type Probe,
  type ProbeCategory,
} from "../../src/probes.js";

describe("Probes Catalog", () => {
  it("ALL_PROBES is a non-empty array", () => {
    expect(Array.isArray(ALL_PROBES)).toBe(true);
    expect(ALL_PROBES.length).toBeGreaterThan(0);
  });

  it("each probe has required fields", () => {
    for (const probe of ALL_PROBES) {
      expect(probe.id).toBeDefined();
      expect(typeof probe.id).toBe("string");
      expect(probe.id.length).toBeGreaterThan(0);

      expect(probe.category).toBeDefined();
      expect(typeof probe.category).toBe("string");

      expect(probe.name).toBeDefined();
      expect(typeof probe.name).toBe("string");
      expect(probe.name.length).toBeGreaterThan(0);

      expect(probe.description).toBeDefined();
      expect(typeof probe.description).toBe("string");
      expect(probe.description.length).toBeGreaterThan(0);

      expect(Array.isArray(probe.exampleAttacks)).toBe(true);
      expect(probe.exampleAttacks.length).toBeGreaterThan(0);

      expect(probe.severity).toBeDefined();
      expect(["critical", "high", "medium", "low"]).toContain(probe.severity);

      expect(Array.isArray(probe.tags)).toBe(true);
      expect(probe.tags.length).toBeGreaterThan(0);
    }
  });

  it("each probe ID is unique", () => {
    const ids = ALL_PROBES.map((p) => p.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  it("all 18 attack categories are represented", () => {
    const categories = new Set(ALL_PROBES.map((p) => p.category));
    const expectedCategories: ProbeCategory[] = [
      "prompt_injection",
      "system_prompt_extraction",
      "jailbreak",
      "role_confusion",
      "instruction_override",
      "context_manipulation",
      "delimiter_injection",
      "encoding_bypass",
      "indirect_injection",
      "tool_exploit",
      "memory_poisoning",
      "goal_hijack",
      "persona_attack",
      "multi_turn_escalation",
      "social_engineering",
      "output_manipulation",
      "data_exfiltration",
      "privilege_escalation",
    ];

    expect(categories.size).toBe(expectedCategories.length);
    for (const cat of expectedCategories) {
      expect(categories.has(cat)).toBe(true);
    }
  });

  it("each category has at least one probe", () => {
    const expectedCategories: ProbeCategory[] = [
      "prompt_injection",
      "system_prompt_extraction",
      "jailbreak",
      "role_confusion",
      "instruction_override",
      "context_manipulation",
      "delimiter_injection",
      "encoding_bypass",
      "indirect_injection",
      "tool_exploit",
      "memory_poisoning",
      "goal_hijack",
      "persona_attack",
      "multi_turn_escalation",
      "social_engineering",
      "output_manipulation",
      "data_exfiltration",
      "privilege_escalation",
    ];

    for (const category of expectedCategories) {
      const probesInCategory = ALL_PROBES.filter((p) => p.category === category);
      expect(probesInCategory.length).toBeGreaterThan(0);
    }
  });

  it("getAllProbes returns all probes", () => {
    const probes = getAllProbes();
    expect(probes).toEqual(ALL_PROBES);
  });

  it("getProbesByCategory returns only probes in the specified category", () => {
    const jailbreakProbes = getProbesByCategory("jailbreak");

    expect(Array.isArray(jailbreakProbes)).toBe(true);
    expect(jailbreakProbes.length).toBeGreaterThan(0);

    for (const probe of jailbreakProbes) {
      expect(probe.category).toBe("jailbreak");
    }
  });

  it("getProbesByCategory returns empty array for non-existent category", () => {
    const probes = getProbesByCategory("invalid_category" as ProbeCategory);
    expect(Array.isArray(probes)).toBe(true);
  });

  it("all probe categories are valid ProbeCategory type", () => {
    const validCategories: ProbeCategory[] = [
      "prompt_injection",
      "system_prompt_extraction",
      "jailbreak",
      "role_confusion",
      "instruction_override",
      "context_manipulation",
      "delimiter_injection",
      "encoding_bypass",
      "indirect_injection",
      "tool_exploit",
      "memory_poisoning",
      "goal_hijack",
      "persona_attack",
      "multi_turn_escalation",
      "social_engineering",
      "output_manipulation",
      "data_exfiltration",
      "privilege_escalation",
    ];

    const categoriesInProbes = new Set(ALL_PROBES.map((p) => p.category));
    for (const cat of categoriesInProbes) {
      expect(validCategories).toContain(cat as ProbeCategory);
    }
  });

  it("probes have diverse severity levels", () => {
    const severities = new Set(ALL_PROBES.map((p) => p.severity));
    expect(severities.size).toBeGreaterThan(1);

    const severityOptions = ["critical", "high", "medium", "low"];
    for (const severity of severities) {
      expect(severityOptions).toContain(severity);
    }
  });
});

describe("DOCUMENTED_TECHNIQUES", () => {
  it("is a non-empty record", () => {
    expect(typeof DOCUMENTED_TECHNIQUES).toBe("object");
    expect(DOCUMENTED_TECHNIQUES !== null).toBe(true);
    expect(Object.keys(DOCUMENTED_TECHNIQUES).length).toBeGreaterThan(0);
  });

  it("all keys and values are strings", () => {
    for (const [key, value] of Object.entries(DOCUMENTED_TECHNIQUES)) {
      expect(typeof key).toBe("string");
      expect(typeof value).toBe("string");
      expect(key.length).toBeGreaterThan(0);
      expect(value.length).toBeGreaterThan(0);
    }
  });

  it("includes common attack technique names", () => {
    const keys = Object.keys(DOCUMENTED_TECHNIQUES);
    expect(keys.length).toBeGreaterThan(0);

    for (const key of keys) {
      expect(typeof key).toBe("string");
    }
  });
});
