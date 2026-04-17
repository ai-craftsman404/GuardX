import { describe, it, expect } from "vitest";
import { TOOL_DEFINITIONS } from "../../src/server.js";

// ---------------------------------------------------------------------------
// Phase 6 smoke tests — verify 3 new tools registered with correct schemas.
// ---------------------------------------------------------------------------

const toolMap = new Map(TOOL_DEFINITIONS.map((t) => [t.name, t]));

describe("phase6 — all 3 new tools registered in server", () => {
  it("test_rag_security is registered", () => {
    expect(toolMap.has("test_rag_security")).toBe(true);
  });

  it("test_agent_escalation is registered", () => {
    expect(toolMap.has("test_agent_escalation")).toBe(true);
  });

  it("scan_supply_chain is registered", () => {
    expect(toolMap.has("scan_supply_chain")).toBe(true);
  });

  it("total tool count is 27", () => {
    expect(TOOL_DEFINITIONS).toHaveLength(33);
  });
});

describe("phase6 — test_rag_security schema", () => {
  const tool = toolMap.get("test_rag_security");

  it("systemPrompt is required", () => {
    expect(tool?.inputSchema.required).toContain("systemPrompt");
  });

  it("categories property has enum with all 6 attack category values", () => {
    const catProp = tool?.inputSchema.properties?.categories as { items?: { enum?: string[] } };
    expect(catProp?.items?.enum).toContain("encoding");
    expect(catProp?.items?.enum).toContain("structural");
    expect(catProp?.items?.enum).toContain("semantic");
    expect(catProp?.items?.enum).toContain("layered");
    expect(catProp?.items?.enum).toContain("trigger");
    expect(catProp?.items?.enum).toContain("exfiltration");
  });

  it("maxDocumentsPerAttack is defined as number type", () => {
    const prop = tool?.inputSchema.properties?.maxDocumentsPerAttack as { type?: string };
    expect(prop?.type).toBe("number");
  });

  it("categories is not required (optional)", () => {
    expect(tool?.inputSchema.required ?? []).not.toContain("categories");
  });

  it("retrievalEndpoint is not required (optional)", () => {
    expect(tool?.inputSchema.required ?? []).not.toContain("retrievalEndpoint");
  });
});

describe("phase6 — test_agent_escalation schema", () => {
  const tool = toolMap.get("test_agent_escalation");

  it("agentHierarchy is required", () => {
    expect(tool?.inputSchema.required).toContain("agentHierarchy");
  });

  it("targetCapability is required", () => {
    expect(tool?.inputSchema.required).toContain("targetCapability");
  });

  it("agentHierarchy is defined as array type", () => {
    const prop = tool?.inputSchema.properties?.agentHierarchy as { type?: string };
    expect(prop?.type).toBe("array");
  });

  it("maxChainDepth is defined as number type", () => {
    const prop = tool?.inputSchema.properties?.maxChainDepth as { type?: string };
    expect(prop?.type).toBe("number");
  });

  it("maxChainDepth is not required (optional)", () => {
    expect(tool?.inputSchema.required ?? []).not.toContain("maxChainDepth");
  });
});

describe("phase6 — scan_supply_chain schema", () => {
  const tool = toolMap.get("scan_supply_chain");

  it("projectPath is required", () => {
    expect(tool?.inputSchema.required).toContain("projectPath");
  });

  it("checkCves is defined as boolean type", () => {
    const prop = tool?.inputSchema.properties?.checkCves as { type?: string };
    expect(prop?.type).toBe("boolean");
  });

  it("checkSecrets is defined as boolean type", () => {
    const prop = tool?.inputSchema.properties?.checkSecrets as { type?: string };
    expect(prop?.type).toBe("boolean");
  });

  it("checkBackdoors is defined as boolean type", () => {
    const prop = tool?.inputSchema.properties?.checkBackdoors as { type?: string };
    expect(prop?.type).toBe("boolean");
  });

  it("scanLoraAdapters is not required (optional)", () => {
    expect(tool?.inputSchema.required ?? []).not.toContain("scanLoraAdapters");
  });
});

describe("phase6 — run_red_team accepts goal-hijack strategy", () => {
  const tool = toolMap.get("run_red_team");

  it("strategy enum includes 'goal-hijack'", () => {
    const stratProp = tool?.inputSchema.properties?.strategy as { enum?: string[] };
    expect(stratProp?.enum).toContain("goal-hijack");
  });

  it("strategy enum still includes blitz, thorough, stealth (no regression)", () => {
    const stratProp = tool?.inputSchema.properties?.strategy as { enum?: string[] };
    expect(stratProp?.enum).toContain("blitz");
    expect(stratProp?.enum).toContain("thorough");
    expect(stratProp?.enum).toContain("stealth");
  });
});

describe("phase6 — scan_extended_probes accepts serialization-rce technique", () => {
  const tool = toolMap.get("scan_extended_probes");

  it("techniques enum includes 'serialization-rce'", () => {
    const techProp = tool?.inputSchema.properties?.techniques as { items?: { enum?: string[] } };
    expect(techProp?.items?.enum).toContain("serialization-rce");
  });

  it("techniques enum still includes flipattack, pap, roleplay (no regression)", () => {
    const techProp = tool?.inputSchema.properties?.techniques as { items?: { enum?: string[] } };
    expect(techProp?.items?.enum).toContain("flipattack");
    expect(techProp?.items?.enum).toContain("pap");
    expect(techProp?.items?.enum).toContain("roleplay");
  });
});
