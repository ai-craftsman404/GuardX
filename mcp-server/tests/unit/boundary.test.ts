import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock zeroleaks before any server import
const mockRunSecurityScan = vi.fn();
const mockGetAllProbes = vi.fn();
const mockGetProbesByCategory = vi.fn();
const mockAllDocumentedTechniques = [
  {
    name: "direct",
    description: "Direct prompt extraction",
    category: "direct",
    successRate: 0.8,
  },
];

vi.mock("zeroleaks", () => ({
  runSecurityScan: mockRunSecurityScan,
  getAllProbes: mockGetAllProbes,
  getProbesByCategory: mockGetProbesByCategory,
  allDocumentedTechniques: mockAllDocumentedTechniques,
}));

// Mock history
const mockListHistory = vi.fn().mockReturnValue([]);
const mockGetHistoryScan = vi.fn().mockReturnValue(null);

vi.mock("../../src/history.js", () => ({
  listHistory: mockListHistory,
  getHistoryScan: mockGetHistoryScan,
  saveScan: vi.fn().mockReturnValue("scan-id"),
}));

// Mock diff
const mockDiffScans = vi.fn();
vi.mock("../../src/diff.js", () => ({
  diffScans: mockDiffScans,
}));

// Mock reports
const mockGenerateHtml = vi.fn().mockReturnValue("/tmp/report.html");
const mockGenerateSarif = vi.fn().mockReturnValue("/tmp/report.sarif.json");
const mockGenerateJunit = vi.fn().mockReturnValue("/tmp/report.xml");
vi.mock("../../src/reports.js", () => ({
  generateHtml: mockGenerateHtml,
  generateSarif: mockGenerateSarif,
  generateJunit: mockGenerateJunit,
}));

// Mock toolcall
vi.mock("../../src/toolcall.js", () => ({
  testToolExfiltration: vi.fn(),
}));

// Minimal mock scan result
const MOCK_SCAN_RESULT = {
  scanId: "scan-123",
  timestamp: "2026-04-03T00:00:00Z",
  vulnerabilityRating: "MEDIUM",
  findings: [
    {
      technique: "direct",
      severity: "HIGH",
      message: "Test finding",
      proof: "Test proof",
    },
  ],
  leakDetected: false,
  promptHash: "abc123",
};

async function getHandleToolCall() {
  const mod = await import("../../src/server.js");
  return mod.handleToolCall;
}

describe("boundary conditions", () => {
  beforeEach(() => {
    process.env.OPENROUTER_API_KEY = "test-key";
    vi.resetModules();
    mockRunSecurityScan.mockReset().mockResolvedValue(MOCK_SCAN_RESULT);
    mockGetHistoryScan.mockReset().mockReturnValue(null);
    mockDiffScans.mockReset();
    mockGenerateHtml.mockReset().mockReturnValue("/tmp/report.html");
    mockGenerateSarif.mockReset().mockReturnValue("/tmp/report.sarif.json");
    mockGenerateJunit.mockReset().mockReturnValue("/tmp/report.xml");
  });

  afterEach(() => {
    vi.resetModules();
  });

  it("scan_system_prompt — 100KB prompt passes to runSecurityScan without error", async () => {
    const handleToolCall = await getHandleToolCall();
    const largePrompt = "A".repeat(102400);

    const result = await handleToolCall("scan_system_prompt", {
      systemPrompt: largePrompt,
    });

    expect(mockRunSecurityScan).toHaveBeenCalledOnce();
    expect(result.isError).toBeFalsy();
  });

  it("scan_system_prompt — unicode/emoji-only prompt is accepted", async () => {
    const handleToolCall = await getHandleToolCall();

    const result = await handleToolCall("scan_system_prompt", {
      systemPrompt: "🔒🛡️🤖💡🔑",
    });

    expect(mockRunSecurityScan).toHaveBeenCalledOnce();
    expect(result.isError).toBeFalsy();
  });

  it("generate_report — 0 findings scan does not throw", async () => {
    const handleToolCall = await getHandleToolCall();
    mockGetHistoryScan.mockReturnValueOnce({
      scanId: "scan-123",
      findings: [],
      timestamp: "2026-04-03T00:00:00Z",
      vulnerabilityRating: "LOW",
      leakDetected: false,
      promptHash: "abc123",
    });

    const result = await handleToolCall("generate_report", {
      id: "scan-123",
      format: "junit",
    });

    expect(result.isError).toBeFalsy();
  });

  it("generate_report — unknown format returns error", async () => {
    const handleToolCall = await getHandleToolCall();

    const result = await handleToolCall("generate_report", {
      scanId: "scan-123",
      format: "docx",
    });

    expect(result.isError).toBeTruthy();
  });

  it("diff_scans — identical baseline and comparison returns no regressions", async () => {
    const handleToolCall = await getHandleToolCall();
    mockDiffScans.mockResolvedValueOnce({
      newFindings: [],
      resolvedFindings: [],
      persistingFindings: [],
      regressionDetected: false,
      vulnerabilityDelta: "none",
      summary: "No changes detected.",
    });

    const result = await handleToolCall("diff_scans", {
      baselineScanId: "scan-baseline",
      currentScanId: "scan-current",
    });

    expect(result.isError).toBeFalsy();
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.regressionDetected).toBe(false);
    expect(parsed.newFindings).toEqual([]);
  });

  it("diff_scans — missing baselineScanId returns error", async () => {
    const handleToolCall = await getHandleToolCall();

    const result = await handleToolCall("diff_scans", {
      currentScanId: "scan-current",
    });

    expect(result.isError).toBeTruthy();
  });

  it("diff_scans — only baselineScanId provided (no currentScanId) is valid", async () => {
    const handleToolCall = await getHandleToolCall();
    mockDiffScans.mockResolvedValueOnce({
      newFindings: [],
      resolvedFindings: [],
      persistingFindings: [],
      regressionDetected: false,
      vulnerabilityDelta: "none",
      summary: "No changes detected.",
    });

    const result = await handleToolCall("diff_scans", {
      baselineScanId: "scan-baseline",
    });

    // No error — currentScanId is optional, server will run a fresh scan
    // (mock prevents actual scan; just verify no crash)
    expect(result.content).toBeDefined();
  });

  it("test_tool_exfiltration — empty availableTools array returns error", async () => {
    const handleToolCall = await getHandleToolCall();

    const result = await handleToolCall("test_tool_exfiltration", {
      systemPrompt: "You are a helpful assistant",
      availableTools: [],
    });

    expect(result.isError).toBeTruthy();
  });

  it("test_tool_exfiltration — missing systemPrompt returns error", async () => {
    const handleToolCall = await getHandleToolCall();

    const result = await handleToolCall("test_tool_exfiltration", {
      availableTools: [
        {
          name: "x",
          description: "y",
          parameters: {
            type: "object",
            properties: {},
            required: [],
          },
        },
      ],
    });

    expect(result.isError).toBeTruthy();
  });

  it("inject_canary — empty string systemPrompt returns error", async () => {
    const handleToolCall = await getHandleToolCall();

    const result = await handleToolCall("inject_canary", {
      systemPrompt: "",
    });

    expect(result.isError).toBeTruthy();
  });

  it("map_findings — empty findings array returns valid response without error", async () => {
    const handleToolCall = await getHandleToolCall();

    const result = await handleToolCall("map_findings", {
      result: { findings: [], overallVulnerability: "none" },
    });

    expect(result.isError).toBeFalsy();
  });

  it("get_scan_result — nonexistent scan ID returns graceful error", async () => {
    const handleToolCall = await getHandleToolCall();
    mockGetHistoryScan.mockReturnValueOnce(null);

    const result = await handleToolCall("get_scan_result", {
      scanId: "nonexistent-id-xyz",
    });

    expect(result.isError).toBeTruthy();
  });
});
