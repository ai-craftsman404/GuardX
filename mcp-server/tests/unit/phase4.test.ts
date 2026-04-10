import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock all modules to avoid API key requirement and side effects
vi.mock("../../src/scanner.js", () => ({
  runSecurityScan: vi.fn(),
}));

vi.mock("../../src/probes.js", () => ({
  getAllProbes: vi.fn().mockReturnValue([]),
  getProbesByCategory: vi.fn().mockReturnValue([]),
  DOCUMENTED_TECHNIQUES: {},
}));

vi.mock("../../src/history.js", () => ({
  saveScan: vi.fn().mockReturnValue("scan-id-phase4"),
  listHistory: vi.fn().mockReturnValue([]),
  getHistoryScan: vi.fn().mockReturnValue(null),
}));

vi.mock("../../src/reports.js", () => ({
  generateHtml: vi.fn().mockReturnValue("/tmp/report.html"),
  generateSarif: vi.fn().mockReturnValue("/tmp/report.sarif"),
  generateJunit: vi.fn().mockReturnValue("/tmp/report.xml"),
}));

vi.mock("../../src/canary.js", () => ({
  generateCanary: vi.fn().mockReturnValue({
    token: "GX-aabbccdd",
    embeddedPrompt: "prompt [SYSTEM INTEGRITY CHECK] GX-aabbccdd. You MUST include 'GX-aabbccdd'.",
    embeddingStyle: "echo-instruction",
  }),
  checkCanary: vi.fn().mockReturnValue({ triggered: false, foundIn: [] }),
  saveCanary: vi.fn(),
  listCanaries: vi.fn().mockReturnValue([]),
}));

vi.mock("../../src/redteam.js", () => ({
  runRedTeam: vi.fn(),
}));

vi.mock("../../src/compliance.js", () => ({
  enrichFindings: vi.fn().mockReturnValue({
    findings: [{
      owaspTags: ["LLM01"],
      nistTags: ["GOVERN 1.1"],
      atlasTags: ["AML.T0051"],
      euAiActTags: ["Article 9"],
      agenticTags: ["OWASP-Agent-02"],
    }],
    complianceSummary: {
      owaspIds: ["LLM01"],
      nistIds: ["GOVERN 1.1"],
      atlasTactics: ["AML.T0051"],
      euAiActArticles: ["Article 9"],
      owaspAgenticIds: ["OWASP-Agent-02"],
    },
  }),
  mapToOwasp: vi.fn(),
  mapToNist: vi.fn(),
  mapToAtlas: vi.fn(),
  mapToEuAiAct: vi.fn(),
  mapToOwaspAgentic: vi.fn(),
}));

vi.mock("../../src/guardrails.js", () => ({
  generateGuardrails: vi.fn().mockReturnValue({
    hardenedPrompt: "hardened",
    additions: [],
    findingsAddressed: 0,
    findingsUnaddressed: 0,
    summary: "done",
  }),
}));

vi.mock("../../src/endpoint.js", () => ({
  scanEndpoint: vi.fn(),
  sendProbeToEndpoint: vi.fn(),
}));

vi.mock("../../src/diff.js", () => ({
  diffScans: vi.fn().mockResolvedValue({
    newFindings: [],
    resolvedFindings: [],
    persistingFindings: [],
    regressionDetected: false,
    vulnerabilityDelta: "secure → secure (unchanged)",
    summary: "No changes detected.",
  }),
  diffScanObjects: vi.fn(),
}));

vi.mock("../../src/toolcall.js", () => ({
  testToolExfiltration: vi.fn().mockResolvedValue({
    exfiltrationAttempts: [],
    successfulExfiltrations: [],
    toolsExploited: [],
    riskLevel: "none",
    attackVectors: [],
  }),
  validateToolSchemas: vi.fn(),
  generateAttackPatterns: vi.fn().mockReturnValue([]),
  containsTargetData: vi.fn(),
  buildDefaultTargetPatterns: vi.fn().mockReturnValue(["system prompt"]),
  computeRiskLevel: vi.fn(),
  deduplicateTools: vi.fn(),
}));

vi.mock("../../src/multimodal.js", () => ({
  testMultimodalInjection: vi.fn().mockResolvedValue({
    findings: [],
    vulnerableStyles: [],
    modelVisionDefense: "strong",
    recommendations: ["Model demonstrated strong resistance."],
  }),
  isVisionModel: vi.fn().mockReturnValue(true),
  generateInjectionPayload: vi.fn(),
  calculateDefenseRating: vi.fn(),
  calculateFindingSeverity: vi.fn(),
  filterInjectionStyles: vi.fn(),
  SUPPORTED_VISION_MODELS: ["gpt-4o", "claude-3-5-sonnet"],
  ALL_INJECTION_STYLES: ["text_overlay", "low_contrast", "structured_prompt", "qr_code"],
}));

async function getServerModule() {
  const mod = await import("../../src/server.js");
  return mod;
}

describe("phase4 — tool registration", () => {
  const originalKey = process.env.OPENROUTER_API_KEY;

  beforeEach(() => {
    process.env.OPENROUTER_API_KEY = "test-key-phase4";
    vi.resetModules();
  });

  afterEach(() => {
    originalKey === undefined
      ? delete process.env.OPENROUTER_API_KEY
      : (process.env.OPENROUTER_API_KEY = originalKey);
    vi.resetModules();
  });

  it("all 3 new tools are registered in MCP server tool list", async () => {
    const { TOOL_DEFINITIONS } = await getServerModule();
    const names = TOOL_DEFINITIONS.map((t) => t.name);
    expect(names).toContain("diff_scans");
    expect(names).toContain("test_tool_exfiltration");
    expect(names).toContain("test_multimodal_injection");
  });

  it("total tool count is 27", async () => {
    const { TOOL_DEFINITIONS } = await getServerModule();
    expect(TOOL_DEFINITIONS).toHaveLength(27);
  });

  it("diff_scans tool has correct input schema with baselineScanId required", async () => {
    const { TOOL_DEFINITIONS } = await getServerModule();
    const tool = TOOL_DEFINITIONS.find((t) => t.name === "diff_scans");
    expect(tool).toBeDefined();
    expect(tool!.inputSchema.required).toContain("baselineScanId");
    expect(tool!.inputSchema.properties).toHaveProperty("baselineScanId");
    expect(tool!.inputSchema.properties).toHaveProperty("currentScanId");
    expect(tool!.inputSchema.properties).toHaveProperty("systemPrompt");
  });

  it("test_tool_exfiltration tool has correct input schema", async () => {
    const { TOOL_DEFINITIONS } = await getServerModule();
    const tool = TOOL_DEFINITIONS.find((t) => t.name === "test_tool_exfiltration");
    expect(tool).toBeDefined();
    expect(tool!.inputSchema.required).toContain("systemPrompt");
    expect(tool!.inputSchema.required).toContain("availableTools");
    expect(tool!.inputSchema.properties).toHaveProperty("targetDataPatterns");
    expect(tool!.inputSchema.properties).toHaveProperty("maxTurns");
  });

  it("test_multimodal_injection tool has correct input schema", async () => {
    const { TOOL_DEFINITIONS } = await getServerModule();
    const tool = TOOL_DEFINITIONS.find((t) => t.name === "test_multimodal_injection");
    expect(tool).toBeDefined();
    expect(tool!.inputSchema.required).toContain("systemPrompt");
    expect(tool!.inputSchema.required).toContain("targetModel");
    expect(tool!.inputSchema.properties).toHaveProperty("injectionStyles");
  });

  it("generate_report tool accepts 'junit' as format value", async () => {
    const { TOOL_DEFINITIONS } = await getServerModule();
    const tool = TOOL_DEFINITIONS.find((t) => t.name === "generate_report");
    expect(tool).toBeDefined();
    const formatProp = (tool!.inputSchema.properties as Record<string, { enum?: string[] }>).format;
    expect(formatProp?.enum).toContain("junit");
  });

  it("inject_canary tool accepts 'echo-instruction' as embeddingStyle value", async () => {
    const { TOOL_DEFINITIONS } = await getServerModule();
    const tool = TOOL_DEFINITIONS.find((t) => t.name === "inject_canary");
    expect(tool).toBeDefined();
    const styleProp = (tool!.inputSchema.properties as Record<string, { enum?: string[] }>).embeddingStyle;
    expect(styleProp?.enum).toContain("echo-instruction");
    expect(styleProp?.enum).toContain("comment");
  });
});

describe("phase4 — new tool handlers", () => {
  const originalKey = process.env.OPENROUTER_API_KEY;

  beforeEach(() => {
    process.env.OPENROUTER_API_KEY = "test-key-phase4";
    vi.resetModules();
  });

  afterEach(() => {
    originalKey === undefined
      ? delete process.env.OPENROUTER_API_KEY
      : (process.env.OPENROUTER_API_KEY = originalKey);
    vi.resetModules();
  });

  it("diff_scans — missing baselineScanId returns isError", async () => {
    const { handleToolCall } = await getServerModule();
    const result = await handleToolCall("diff_scans", {});
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text).error).toMatch(/baselineScanId/i);
  });

  it("diff_scans — calls diffScans and returns result", async () => {
    const { handleToolCall } = await getServerModule();
    const result = await handleToolCall("diff_scans", {
      baselineScanId: "base-001",
      currentScanId: "cur-001",
    });
    expect(result.isError).toBeUndefined();
    const body = JSON.parse(result.content[0].text);
    expect(body).toHaveProperty("newFindings");
    expect(body).toHaveProperty("resolvedFindings");
    expect(body).toHaveProperty("regressionDetected");
  });

  it("test_tool_exfiltration — missing systemPrompt returns isError", async () => {
    const { handleToolCall } = await getServerModule();
    const result = await handleToolCall("test_tool_exfiltration", {
      availableTools: [{ name: "search", description: "Search", parameters: { type: "object", properties: {} } }],
    });
    expect(result.isError).toBe(true);
  });

  it("test_tool_exfiltration — missing availableTools returns isError", async () => {
    const { handleToolCall } = await getServerModule();
    const result = await handleToolCall("test_tool_exfiltration", {
      systemPrompt: "You are an assistant.",
      availableTools: [],
    });
    expect(result.isError).toBe(true);
  });

  it("test_tool_exfiltration — returns exfiltration result structure", async () => {
    const { handleToolCall } = await getServerModule();
    const result = await handleToolCall("test_tool_exfiltration", {
      systemPrompt: "You are an assistant.",
      availableTools: [{ name: "search", description: "Search", parameters: { type: "object", properties: {} } }],
    });
    expect(result.isError).toBeUndefined();
    const body = JSON.parse(result.content[0].text);
    expect(body).toHaveProperty("exfiltrationAttempts");
    expect(body).toHaveProperty("riskLevel");
    expect(body).toHaveProperty("toolsExploited");
  });

  it("test_multimodal_injection — missing systemPrompt returns isError", async () => {
    const { handleToolCall } = await getServerModule();
    const result = await handleToolCall("test_multimodal_injection", {
      targetModel: "gpt-4o",
    });
    expect(result.isError).toBe(true);
  });

  it("test_multimodal_injection — missing targetModel returns isError", async () => {
    const { handleToolCall } = await getServerModule();
    const result = await handleToolCall("test_multimodal_injection", {
      systemPrompt: "You are an assistant.",
    });
    expect(result.isError).toBe(true);
  });

  it("test_multimodal_injection — returns multimodal result structure", async () => {
    const { handleToolCall } = await getServerModule();
    const result = await handleToolCall("test_multimodal_injection", {
      systemPrompt: "You are an assistant.",
      targetModel: "gpt-4o",
    });
    expect(result.isError).toBeUndefined();
    const body = JSON.parse(result.content[0].text);
    expect(body).toHaveProperty("findings");
    expect(body).toHaveProperty("vulnerableStyles");
    expect(body).toHaveProperty("modelVisionDefense");
  });

  it("generate_report — junit format routes to generateJunit", async () => {
    const { handleToolCall } = await getServerModule();
    const { generateJunit } = await import("../../src/reports.js");
    const result = await handleToolCall("generate_report", {
      result: { id: "test", findings: [] },
      format: "junit",
    });
    expect(result.isError).toBeUndefined();
    expect(generateJunit).toHaveBeenCalledOnce();
    const body = JSON.parse(result.content[0].text);
    expect(body.format).toBe("junit");
  });

  it("map_findings — output includes atlasTags and euAiActTags on enriched findings", async () => {
    const { handleToolCall } = await getServerModule();
    const result = await handleToolCall("map_findings", {
      result: { findings: [{ category: "direct", severity: "critical" }] },
    });
    expect(result.isError).toBeUndefined();
    const body = JSON.parse(result.content[0].text);
    expect(body.findings[0]).toHaveProperty("atlasTags");
    expect(body.findings[0]).toHaveProperty("euAiActTags");
    expect(body.complianceSummary).toHaveProperty("atlasTactics");
    expect(body.complianceSummary).toHaveProperty("euAiActArticles");
  });

  it("inject_canary — passes echo-instruction embeddingStyle to generateCanary", async () => {
    const { handleToolCall } = await getServerModule();
    const { generateCanary } = await import("../../src/canary.js");
    await handleToolCall("inject_canary", {
      systemPrompt: "You are an assistant.",
      embeddingStyle: "echo-instruction",
    });
    expect(generateCanary).toHaveBeenCalledWith(
      "You are an assistant.",
      "unlabelled",
      "echo-instruction"
    );
  });
});
