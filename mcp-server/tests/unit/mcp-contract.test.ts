import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";

const mockRunSecurityScan = vi.fn();
const mockGetAllProbes = vi.fn();
const mockGetProbesByCategory = vi.fn();
vi.mock("zeroleaks", () => ({
  runSecurityScan: mockRunSecurityScan,
  getAllProbes: mockGetAllProbes,
  getProbesByCategory: mockGetProbesByCategory,
  allDocumentedTechniques: [
    {
      id: "t1",
      category: "direct",
      name: "Test",
      description: "Test technique",
    },
  ],
}));

vi.mock("../../src/history.js", () => ({
  saveScan: vi.fn().mockReturnValue("scan-123"),
  listHistory: vi.fn().mockReturnValue([]),
  getHistoryScan: vi.fn().mockReturnValue(null),
}));

vi.mock("../../src/reports.js", () => ({
  generateHtml: vi.fn().mockReturnValue("/tmp/r.html"),
  generateSarif: vi.fn().mockReturnValue("/tmp/r.json"),
  generateJunit: vi.fn().mockReturnValue("/tmp/r.xml"),
}));

vi.mock("../../src/canary.js", () => ({
  generateCanary: vi.fn().mockReturnValue({
    token: "GX-test1234",
    embeddedPrompt: "prompt",
    embeddingStyle: "echo-instruction",
  }),
  checkCanary: vi.fn().mockReturnValue({ triggered: false, foundIn: [] }),
  saveCanary: vi.fn(),
  listCanaries: vi.fn().mockReturnValue([]),
}));

vi.mock("../../src/redteam.js", () => ({
  runRedTeam: vi.fn().mockResolvedValue({ passed: true }),
}));

vi.mock("../../src/compliance.js", () => ({
  enrichFindings: vi.fn().mockReturnValue([]),
}));

vi.mock("../../src/guardrails.js", () => ({
  generateGuardrails: vi.fn().mockReturnValue({ guardrails: [] }),
}));

vi.mock("../../src/endpoint.js", () => ({
  scanEndpoint: vi.fn().mockResolvedValue({ findings: [] }),
}));

vi.mock("../../src/diff.js", () => ({
  diffScans: vi.fn().mockReturnValue({
    regressions: [],
    improvements: [],
    unchanged: [],
  }),
}));

vi.mock("../../src/toolcall.js", () => ({
  testToolExfiltration: vi.fn().mockResolvedValue({
    exfiltrationAttempts: [],
    successfulExfiltrations: [],
    riskLevel: "none",
    toolsExploited: [],
    attackVectors: [],
  }),
}));

vi.mock("../../src/multimodal.js", () => ({
  testMultimodalInjection: vi.fn().mockResolvedValue({
    findings: [],
    vulnerableStyles: [],
    modelVisionDefense: "strong",
    recommendations: [],
  }),
}));

const MOCK_SCAN_RESULT = {
  scanId: "scan-123",
  timestamp: new Date().toISOString(),
  systemPrompt: "You are a helpful assistant.",
  mode: "dual" as const,
  findings: [],
  vulnerabilityRating: "none" as const,
  leakageDetected: false,
  injectionVulnerability: false,
  successRate: 0,
  defenseProfile: {
    systemPromptProtection: "strong",
    inputValidation: "strong",
    outputFiltering: "strong",
    contextIsolation: "strong",
    modelAlignment: "strong",
  },
  recommendations: [],
  promptHash: "hash123",
};

let client: Client;

beforeEach(async () => {
  process.env.OPENROUTER_API_KEY = "test-key-contract";
  vi.resetModules();
  mockRunSecurityScan.mockReset().mockResolvedValue(MOCK_SCAN_RESULT);
  mockGetAllProbes.mockReset().mockReturnValue([]);
  mockGetProbesByCategory.mockReset().mockReturnValue([]);

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const mod = await import("../../src/server.js");
  const server = mod.buildServer();
  await server.connect(serverTransport);

  client = new Client(
    { name: "test-client", version: "1.0.0" },
    { capabilities: {} }
  );
  await client.connect(clientTransport);
});

afterEach(async () => {
  await client.close();
  vi.resetModules();
  delete process.env.OPENROUTER_API_KEY;
});

describe("MCP protocol contract", () => {
  it("listTools returns exactly 25 tools", async () => {
    const result = await client.listTools();
    expect(result.tools.length).toBe(25);
  });

  it("listTools — every tool has name, description, and inputSchema", async () => {
    const result = await client.listTools();
    result.tools.forEach((tool) => {
      expect(typeof tool.name).toBe("string");
      expect(typeof tool.description).toBe("string");
      expect(typeof tool.inputSchema).toBe("object");
    });
  });

  it("callTool scan_system_prompt — response has content array with text type", async () => {
    const result = await client.callTool({
      name: "scan_system_prompt",
      arguments: { systemPrompt: "You are a test assistant." },
    });
    expect(Array.isArray(result.content)).toBe(true);
    expect(result.content[0].type).toBe("text");
    expect(() => {
      JSON.parse(result.content[0].text as string);
    }).not.toThrow();
  });

  it("callTool scan_system_prompt — missing systemPrompt returns isError true via content", async () => {
    const result = await client.callTool({
      name: "scan_system_prompt",
      arguments: {},
    });
    const body = JSON.parse(result.content[0].text as string);
    expect(body.error).toMatch(/systemPrompt/);
  });

  it("callTool list_probes — returns valid response without isError", async () => {
    const result = await client.callTool({
      name: "list_probes",
      arguments: {},
    });
    expect(result.isError).toBeFalsy();
    expect(() => {
      JSON.parse(result.content[0].text as string);
    }).not.toThrow();
  });

  it("callTool unknown tool name — returns error response", async () => {
    let caught: unknown;
    let result: Awaited<ReturnType<typeof client.callTool>> | undefined;
    try {
      result = await client.callTool({
        name: "nonexistent_tool_xyz",
        arguments: {},
      });
    } catch (e) {
      caught = e;
    }
    // Either the server returns isError:true, OR the SDK throws — both are valid error responses
    // But at least one must be true (cannot silently succeed)
    if (caught !== undefined) {
      expect(caught).toBeInstanceOf(Error);
    } else {
      expect(result!.isError).toBe(true);
    }
  });
});
