import { describe, it, expect } from "vitest";
import { TOOL_DEFINITIONS } from "../../src/server.js";

// ---------------------------------------------------------------------------
// Phase 5 smoke tests — verify all 5 new tools are registered with
// correct schemas, without invoking any external APIs.
// ---------------------------------------------------------------------------

const toolMap = new Map(TOOL_DEFINITIONS.map((t) => [t.name, t]));

describe("phase5 — all 5 new tools registered in server", () => {
  it("scan_extended_probes is registered", () => {
    expect(toolMap.has("scan_extended_probes")).toBe(true);
  });

  it("test_mcp_security is registered", () => {
    expect(toolMap.has("test_mcp_security")).toBe(true);
  });

  it("create_scheduled_scan is registered", () => {
    expect(toolMap.has("create_scheduled_scan")).toBe(true);
  });

  it("list_scheduled_scans is registered", () => {
    expect(toolMap.has("list_scheduled_scans")).toBe(true);
  });

  it("delete_scheduled_scan is registered", () => {
    expect(toolMap.has("delete_scheduled_scan")).toBe(true);
  });

  it("total tool count is 27", () => {
    expect(TOOL_DEFINITIONS).toHaveLength(27);
  });
});

describe("phase5 — scan_extended_probes schema", () => {
  const tool = toolMap.get("scan_extended_probes");

  it("systemPrompt is required", () => {
    expect(tool?.inputSchema.required).toContain("systemPrompt");
  });

  it("techniques property has enum with all three technique values", () => {
    const techProp = tool?.inputSchema.properties?.techniques as {
      items?: { enum?: string[] };
    };
    expect(techProp?.items?.enum).toContain("flipattack");
    expect(techProp?.items?.enum).toContain("pap");
    expect(techProp?.items?.enum).toContain("roleplay");
  });

  it("maxAttemptsPerTechnique property is defined as number type", () => {
    const prop = tool?.inputSchema.properties?.maxAttemptsPerTechnique as {
      type?: string;
    };
    expect(prop?.type).toBe("number");
  });

  it("techniques is not required (optional)", () => {
    expect(tool?.inputSchema.required ?? []).not.toContain("techniques");
  });
});

describe("phase5 — test_mcp_security schema", () => {
  const tool = toolMap.get("test_mcp_security");

  it("systemPrompt is required", () => {
    expect(tool?.inputSchema.required).toContain("systemPrompt");
  });

  it("mcpToolSchemas is required", () => {
    expect(tool?.inputSchema.required).toContain("mcpToolSchemas");
  });

  it("mcpToolSchemas is defined as array type", () => {
    const prop = tool?.inputSchema.properties?.mcpToolSchemas as {
      type?: string;
    };
    expect(prop?.type).toBe("array");
  });

  it("sensitivePatterns property is defined", () => {
    expect(tool?.inputSchema.properties).toHaveProperty("sensitivePatterns");
  });

  it("sensitivePatterns is not required (optional — defaults to standard patterns)", () => {
    expect(tool?.inputSchema.required ?? []).not.toContain("sensitivePatterns");
  });
});

describe("phase5 — create_scheduled_scan schema", () => {
  const tool = toolMap.get("create_scheduled_scan");

  it("name is required", () => {
    expect(tool?.inputSchema.required).toContain("name");
  });

  it("cronExpression is required", () => {
    expect(tool?.inputSchema.required).toContain("cronExpression");
  });

  it("systemPrompt and promptFile are not required (mutually exclusive optional)", () => {
    expect(tool?.inputSchema.required ?? []).not.toContain("systemPrompt");
    expect(tool?.inputSchema.required ?? []).not.toContain("promptFile");
  });

  it("webhookUrl property is defined", () => {
    expect(tool?.inputSchema.properties).toHaveProperty("webhookUrl");
  });

  it("webhookOnSeverity property is defined with correct enum items", () => {
    const prop = tool?.inputSchema.properties?.webhookOnSeverity as {
      items?: { enum?: string[] };
    };
    expect(prop?.items?.enum).toContain("critical");
    expect(prop?.items?.enum).toContain("high");
    expect(prop?.items?.enum).toContain("medium");
    expect(prop?.items?.enum).toContain("low");
  });

  it("mode property has correct enum values", () => {
    const prop = tool?.inputSchema.properties?.mode as { enum?: string[] };
    expect(prop?.enum).toContain("extraction");
    expect(prop?.enum).toContain("injection");
    expect(prop?.enum).toContain("dual");
  });
});

describe("phase5 — list_scheduled_scans schema", () => {
  const tool = toolMap.get("list_scheduled_scans");

  it("tool is defined", () => {
    expect(tool).toBeDefined();
  });

  it("has no required fields (no arguments needed)", () => {
    expect((tool?.inputSchema.required ?? []).length).toBe(0);
  });
});

describe("phase5 — delete_scheduled_scan schema", () => {
  const tool = toolMap.get("delete_scheduled_scan");

  it("scheduleId is required", () => {
    expect(tool?.inputSchema.required).toContain("scheduleId");
  });

  it("scheduleId is defined as string type", () => {
    const prop = tool?.inputSchema.properties?.scheduleId as { type?: string };
    expect(prop?.type).toBe("string");
  });
});

describe("phase5 — generate_report accepts 'pdf' format", () => {
  const tool = toolMap.get("generate_report");

  it("format enum includes 'pdf'", () => {
    const formatProp = tool?.inputSchema.properties?.format as {
      enum?: string[];
    };
    expect(formatProp?.enum).toContain("pdf");
  });

  it("format enum still includes html, sarif, junit — no regression", () => {
    const formatProp = tool?.inputSchema.properties?.format as {
      enum?: string[];
    };
    expect(formatProp?.enum).toContain("html");
    expect(formatProp?.enum).toContain("sarif");
    expect(formatProp?.enum).toContain("junit");
  });
});

describe("phase5 — map_findings output includes agenticTags and owaspAgenticIds", () => {
  it("enrichFindings adds agenticTags to findings", async () => {
    const { enrichFindings } = await import("../../src/compliance.js");
    const result = enrichFindings({
      findings: [{ category: "tool_exploit", severity: "critical" }],
    });
    expect(Array.isArray(result.findings[0].agenticTags)).toBe(true);
    expect(result.findings[0].agenticTags).toContain("OWASP-Agent-04");
  });

  it("enrichFindings complianceSummary includes owaspAgenticIds", async () => {
    const { enrichFindings } = await import("../../src/compliance.js");
    const result = enrichFindings({
      findings: [{ category: "direct", severity: "high" }],
    });
    expect(Array.isArray(result.complianceSummary.owaspAgenticIds)).toBe(true);
    expect(result.complianceSummary.owaspAgenticIds.length).toBeGreaterThan(0);
  });
});
