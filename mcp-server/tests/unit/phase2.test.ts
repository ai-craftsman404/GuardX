import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock scanner and probes
const mockRunSecurityScan = vi.fn();
const mockGetAllProbes = vi.fn();
const mockGetProbesByCategory = vi.fn();
vi.mock("../../src/scanner.js", () => ({
  runSecurityScan: mockRunSecurityScan,
}));
vi.mock("../../src/probes.js", () => ({
  getAllProbes: mockGetAllProbes,
  getProbesByCategory: mockGetProbesByCategory,
  DOCUMENTED_TECHNIQUES: {},
}));

// Mock history module
const mockSaveScan = vi.fn();
const mockListHistory = vi.fn();
const mockGetHistoryScan = vi.fn();
vi.mock("../../src/history.js", () => ({
  saveScan: mockSaveScan,
  listHistory: mockListHistory,
  getHistoryScan: mockGetHistoryScan,
}));

// Mock reports module
const mockGenerateHtml = vi.fn();
const mockGenerateSarif = vi.fn();
vi.mock("../../src/reports.js", () => ({
  generateHtml: mockGenerateHtml,
  generateSarif: mockGenerateSarif,
}));

const MOCK_SCAN_RESULT = {
  findings: [
    {
      id: "f1",
      severity: "high",
      technique: "direct_extraction",
      category: "direct",
      extractedContent: "You are a helpful assistant",
      confidence: "high",
      evidence: "Model repeated system prompt verbatim",
    },
  ],
  overallVulnerability: "high",
  leakStatus: "substantial",
  recommendations: ["Add secrecy instructions"],
  defenseProfile: { level: "weak", guardrails: [], weaknesses: [] },
  turnsUsed: 10,
  tokensUsed: 2000,
  duration: 20000,
};

const MOCK_HISTORY: import("../../src/history.js").ScanHistoryMeta[] = [
  {
    id: "1743000000000-abc1234",
    scannedAt: "2026-03-26T10:00:00.000Z",
    vulnerability: "high",
    leakStatus: "substantial",
    promptHash: "deadbeef",
    findingsCount: 2,
  },
  {
    id: "1742900000000-xyz5678",
    scannedAt: "2026-03-25T08:00:00.000Z",
    vulnerability: "low",
    leakStatus: "none",
    promptHash: "cafebabe",
    findingsCount: 0,
  },
];

async function getHandleToolCall() {
  const mod = await import("../../src/server.js");
  return mod.handleToolCall;
}

describe("GuardX Phase 2 — scan history and reports", () => {
  const originalKey = process.env.OPENROUTER_API_KEY;

  beforeEach(() => {
    process.env.OPENROUTER_API_KEY = "test-key-phase2";
    mockRunSecurityScan.mockReset().mockResolvedValue(MOCK_SCAN_RESULT);
    mockSaveScan.mockReset().mockReturnValue("1743000000000-abc1234");
    mockListHistory.mockReset().mockReturnValue(MOCK_HISTORY);
    mockGetHistoryScan.mockReset().mockReturnValue({ ...MOCK_SCAN_RESULT, id: "1743000000000-abc1234", promptHash: "deadbeef", scannedAt: "2026-03-26T10:00:00.000Z" });
    mockGenerateHtml.mockReset().mockReturnValue("/project/.guardx/reports/1743000000000-abc1234.html");
    mockGenerateSarif.mockReset().mockReturnValue("/project/.guardx/reports/1743000000000-abc1234.sarif");
    mockGetAllProbes.mockReset().mockReturnValue([]);
    mockGetProbesByCategory.mockReset().mockReturnValue([]);
    vi.resetModules();
  });

  afterEach(() => {
    originalKey === undefined
      ? delete process.env.OPENROUTER_API_KEY
      : (process.env.OPENROUTER_API_KEY = originalKey);
    vi.resetModules();
  });

  // --- Auto-save ---

  it("scan_system_prompt — auto-saves result to history after successful scan", async () => {
    const handleToolCall = await getHandleToolCall();
    const result = await handleToolCall("scan_system_prompt", {
      systemPrompt: "You are a test assistant.",
    });
    expect(result.isError).toBeUndefined();
    expect(mockSaveScan).toHaveBeenCalledOnce();
    expect(mockSaveScan).toHaveBeenCalledWith(
      expect.objectContaining({ overallVulnerability: "high" }),
      "You are a test assistant."
    );
  });

  it("scan_system_prompt — includes scanId in response", async () => {
    const handleToolCall = await getHandleToolCall();
    const result = await handleToolCall("scan_system_prompt", {
      systemPrompt: "You are a test assistant.",
    });
    const body = JSON.parse(result.content[0].text);
    expect(body).toHaveProperty("scanId", "1743000000000-abc1234");
  });

  it("scan_system_prompt — response body contains findings, overallVulnerability, and leakStatus", async () => {
    const handleToolCall = await getHandleToolCall();
    const result = await handleToolCall("scan_system_prompt", {
      systemPrompt: "You are a test assistant.",
    });
    expect(result.isError).toBeUndefined();
    const body = JSON.parse(result.content[0].text);
    expect(body).toHaveProperty("overallVulnerability", "high");
    expect(body).toHaveProperty("leakStatus", "substantial");
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.findings).toHaveLength(1);
  });

  it("scan_system_prompt — history save failure does not break scan response", async () => {
    mockSaveScan.mockImplementationOnce(() => { throw new Error("disk full"); });
    const handleToolCall = await getHandleToolCall();
    const result = await handleToolCall("scan_system_prompt", {
      systemPrompt: "You are a test assistant.",
    });
    expect(result.isError).toBeUndefined();
    const body = JSON.parse(result.content[0].text);
    expect(body).toHaveProperty("overallVulnerability");
  });

  // --- list_scan_history ---

  it("list_scan_history — returns history entries ordered newest first", async () => {
    const handleToolCall = await getHandleToolCall();
    const result = await handleToolCall("list_scan_history", {});
    expect(result.isError).toBeUndefined();
    const body = JSON.parse(result.content[0].text);
    expect(Array.isArray(body)).toBe(true);
    expect(body).toHaveLength(2);
    expect(body[0]).toHaveProperty("id", "1743000000000-abc1234");
    expect(body[0]).toHaveProperty("vulnerability", "high");
    expect(body[0]).toHaveProperty("promptHash", "deadbeef");
    expect(body[0]).toHaveProperty("findingsCount", 2);
  });

  it("list_scan_history — returns empty array when no history", async () => {
    mockListHistory.mockReturnValueOnce([]);
    const handleToolCall = await getHandleToolCall();
    const result = await handleToolCall("list_scan_history", {});
    const body = JSON.parse(result.content[0].text);
    expect(body).toEqual([]);
  });

  // --- get_scan_result ---

  it("get_scan_result — returns full scan for known id", async () => {
    const handleToolCall = await getHandleToolCall();
    const result = await handleToolCall("get_scan_result", {
      id: "1743000000000-abc1234",
    });
    expect(result.isError).toBeUndefined();
    const body = JSON.parse(result.content[0].text);
    expect(body).toHaveProperty("overallVulnerability", "high");
    expect(body).toHaveProperty("promptHash", "deadbeef");
    expect(mockGetHistoryScan).toHaveBeenCalledWith("1743000000000-abc1234");
  });

  it("get_scan_result — returns error for unknown id", async () => {
    mockGetHistoryScan.mockReturnValueOnce(null);
    const handleToolCall = await getHandleToolCall();
    const result = await handleToolCall("get_scan_result", { id: "nonexistent-id" });
    expect(result.isError).toBe(true);
    const body = JSON.parse(result.content[0].text);
    expect(body.error).toMatch(/nonexistent-id/);
  });

  it("get_scan_result — returns error when id is missing", async () => {
    const handleToolCall = await getHandleToolCall();
    const result = await handleToolCall("get_scan_result", {});
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text).error).toMatch(/id/);
  });

  // --- generate_report ---

  it("generate_report html — loads from history by id and calls generateHtml", async () => {
    const handleToolCall = await getHandleToolCall();
    const result = await handleToolCall("generate_report", {
      id: "1743000000000-abc1234",
      format: "html",
    });
    expect(result.isError).toBeUndefined();
    expect(mockGenerateHtml).toHaveBeenCalledOnce();
    expect(mockGenerateSarif).not.toHaveBeenCalled();
    const body = JSON.parse(result.content[0].text);
    expect(body).toHaveProperty("filePath");
    expect(body.filePath).toMatch(/\.html$/);
    expect(body).toHaveProperty("format", "html");
  });

  it("generate_report sarif — loads from history by id and calls generateSarif", async () => {
    const handleToolCall = await getHandleToolCall();
    const result = await handleToolCall("generate_report", {
      id: "1743000000000-abc1234",
      format: "sarif",
    });
    expect(result.isError).toBeUndefined();
    expect(mockGenerateSarif).toHaveBeenCalledOnce();
    expect(mockGenerateHtml).not.toHaveBeenCalled();
    const body = JSON.parse(result.content[0].text);
    expect(body.filePath).toMatch(/\.sarif$/);
    expect(body).toHaveProperty("format", "sarif");
  });

  it("generate_report — accepts inline result object instead of id", async () => {
    const handleToolCall = await getHandleToolCall();
    const result = await handleToolCall("generate_report", {
      result: MOCK_SCAN_RESULT,
      format: "html",
    });
    expect(result.isError).toBeUndefined();
    expect(mockGetHistoryScan).not.toHaveBeenCalled();
    expect(mockGenerateHtml).toHaveBeenCalledOnce();
  });

  it("generate_report — defaults to html when format is omitted", async () => {
    const handleToolCall = await getHandleToolCall();
    await handleToolCall("generate_report", { id: "1743000000000-abc1234" });
    expect(mockGenerateHtml).toHaveBeenCalledOnce();
    expect(mockGenerateSarif).not.toHaveBeenCalled();
  });

  it("generate_report — returns error when neither id nor result is provided", async () => {
    const handleToolCall = await getHandleToolCall();
    const result = await handleToolCall("generate_report", {});
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text).error).toMatch(/id.*result|result.*id/i);
  });

  it("generate_report — returns error when id is not found in history", async () => {
    mockGetHistoryScan.mockReturnValueOnce(null);
    const handleToolCall = await getHandleToolCall();
    const result = await handleToolCall("generate_report", { id: "ghost-id" });
    expect(result.isError).toBe(true);
  });

  it("generate_report html — returns isError and error message when generateHtml throws", async () => {
    mockGetHistoryScan.mockReturnValueOnce({ ...MOCK_SCAN_RESULT, id: "1743000000000-abc1234" });
    mockGenerateHtml.mockImplementationOnce(() => {
      throw new Error("ENOSPC: no space left on device");
    });
    const handleToolCall = await getHandleToolCall();
    const result = await handleToolCall("generate_report", {
      id: "1743000000000-abc1234",
      format: "html",
    });
    expect(result.isError).toBe(true);
    const body = JSON.parse(result.content[0].text);
    expect(body.error).toMatch(/ENOSPC/);
    expect(body.error).toMatch(/Report generation failed/);
  });

  it("generate_report sarif — returns isError and error message when generateSarif throws", async () => {
    mockGetHistoryScan.mockReturnValueOnce({ ...MOCK_SCAN_RESULT, id: "1743000000000-abc1234" });
    mockGenerateSarif.mockImplementationOnce(() => {
      throw new Error("EPERM: permission denied");
    });
    const handleToolCall = await getHandleToolCall();
    const result = await handleToolCall("generate_report", {
      id: "1743000000000-abc1234",
      format: "sarif",
    });
    expect(result.isError).toBe(true);
    const body = JSON.parse(result.content[0].text);
    expect(body.error).toMatch(/EPERM/);
    expect(body.error).toMatch(/Report generation failed/);
  });
});
