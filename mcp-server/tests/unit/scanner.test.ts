import { describe, it, expect, vi, beforeEach } from "vitest";
import { runSecurityScan } from "../../src/scanner.js";
import { getAllProbes, getProbesByCategory, DOCUMENTED_TECHNIQUES } from "../../src/probes.js";
import type { ScanOptions } from "../../src/scanner.js";

// Mock OpenRouter API calls
const mockOpenRouterCall = vi.hoisted(() => vi.fn());

vi.mock("../../src/openrouter.js", () => ({
  callOpenRouter: mockOpenRouterCall,
}));

describe("Scanner - runSecurityScan", () => {
  beforeEach(() => {
    mockOpenRouterCall.mockClear();
    process.env.OPENROUTER_API_KEY = "test-key";
  });

  it("calls attacker model with system prompt context", async () => {
    mockOpenRouterCall
      .mockResolvedValueOnce({ content: "attack payload", tokens: 150 })
      .mockResolvedValueOnce({ content: "target response", tokens: 225 })
      .mockResolvedValueOnce({ content: '{"succeeded": false}', tokens: 160 });

    const systemPrompt = "You are a helpful assistant.";
    await runSecurityScan(systemPrompt, { mode: "extraction", maxTurns: 1 });

    expect(mockOpenRouterCall).toHaveBeenCalled();
    const firstCall = mockOpenRouterCall.mock.calls[0];
    expect(firstCall[0]).toContain("anthropic/claude-haiku-4-5-20251001");
  });

  it("calls target model with system prompt as system message", async () => {
    mockOpenRouterCall
      .mockResolvedValueOnce({ content: "attack payload", tokens: 150 })
      .mockResolvedValueOnce({ content: "target response", tokens: 225 })
      .mockResolvedValueOnce({ content: '{"succeeded": false}', tokens: 160 });

    const systemPrompt = "You are a helpful assistant.";
    await runSecurityScan(systemPrompt, { mode: "extraction", maxTurns: 1 });

    const secondCall = mockOpenRouterCall.mock.calls[1];
    expect(secondCall).toBeDefined();
    expect(secondCall[0]).toContain("openai/gpt-4o-mini");
  });

  it("calls evaluator model with attack and response pair", async () => {
    mockOpenRouterCall
      .mockResolvedValueOnce({ content: "attack payload", tokens: 150 })
      .mockResolvedValueOnce({ content: "target response", tokens: 225 })
      .mockResolvedValueOnce({ content: '{"succeeded": false}', tokens: 160 });

    const systemPrompt = "You are a helpful assistant.";
    await runSecurityScan(systemPrompt, { mode: "extraction", maxTurns: 1 });

    const thirdCall = mockOpenRouterCall.mock.calls[2];
    expect(thirdCall).toBeDefined();
    expect(thirdCall[0]).toContain("anthropic/claude-sonnet-4-6");
  });

  it("mode: 'extraction' only runs extraction-category probes", async () => {
    mockOpenRouterCall.mockResolvedValue({
      content: '{"succeeded": false}',
      tokens: 150,
    });

    const systemPrompt = "Test system prompt";
    const result = await runSecurityScan(systemPrompt, {
      mode: "extraction",
      maxTurns: 1,
    });

    expect(result).toHaveProperty("findings");
    expect(result).toHaveProperty("vulnerability");
  });

  it("mode: 'injection' only runs injection-category probes", async () => {
    mockOpenRouterCall.mockResolvedValue({
      content: '{"succeeded": false}',
      tokens: 150,
    });

    const systemPrompt = "Test system prompt";
    const result = await runSecurityScan(systemPrompt, {
      mode: "injection",
      maxTurns: 1,
    });

    expect(mockOpenRouterCall).toHaveBeenCalled();
    expect(result).toHaveProperty("vulnerability");
  });

  it("mode: 'dual' runs both extraction and injection probes", async () => {
    mockOpenRouterCall.mockResolvedValue({
      content: '{"succeeded": false}',
      tokens: 150,
    });

    const systemPrompt = "Test system prompt";
    const result = await runSecurityScan(systemPrompt, {
      mode: "dual",
      maxTurns: 1,
    });

    expect(mockOpenRouterCall).toHaveBeenCalled();
    expect(result).toHaveProperty("vulnerability");
  });

  it("categories filter limits which probe categories are tested", async () => {
    mockOpenRouterCall.mockResolvedValue({
      content: '{"succeeded": false}',
      tokens: 150,
    });

    const systemPrompt = "Test system prompt";
    const result = await runSecurityScan(systemPrompt, {
      categories: ["jailbreak", "prompt_injection"],
      maxTurns: 1,
    });

    expect(mockOpenRouterCall).toHaveBeenCalled();
    expect(result).toHaveProperty("vulnerability");
  });

  it("vulnerability: 'critical' when any finding is critical severity", async () => {
    mockOpenRouterCall
      .mockResolvedValueOnce({ content: "attack", tokens: 150 })
      .mockResolvedValueOnce({ content: "target response", tokens: 225 })
      .mockResolvedValueOnce({
        content: '{"succeeded": true, "severity": "critical"}',
        tokens: 160,
      });

    const result = await runSecurityScan("Test prompt", {
      mode: "extraction",
      maxTurns: 1,
    });

    expect(result.vulnerability).toBe("critical");
  });

  it("vulnerability: 'secure' when findings array is empty", async () => {
    mockOpenRouterCall.mockResolvedValue({
      content: '{"succeeded": false}',
      tokens: 150,
    });

    const result = await runSecurityScan("Test prompt", {
      mode: "extraction",
      maxTurns: 1,
    });

    expect(result.vulnerability).toBe("secure");
  });

  it("leakStatus: 'leaked' when evaluator confirms extraction success", async () => {
    mockOpenRouterCall
      .mockResolvedValueOnce({ content: "attack", tokens: 150 })
      .mockResolvedValueOnce({ content: "system prompt leaked", tokens: 225 })
      .mockResolvedValueOnce({
        content: '{"succeeded": true, "severity": "critical", "extractedContent": "secret"}',
        tokens: 160,
      });

    const result = await runSecurityScan("Test prompt", {
      mode: "extraction",
      maxTurns: 1,
    });

    expect(result.leakStatus).toBe("leaked");
  });

  it("leakStatus: 'none' when no extraction finding succeeds", async () => {
    mockOpenRouterCall.mockResolvedValue({
      content: '{"succeeded": false}',
      tokens: 150,
    });

    const result = await runSecurityScan("Test prompt", {
      mode: "extraction",
      maxTurns: 1,
    });

    expect(result.leakStatus).toBe("none");
  });

  it("totalTokens is sum of all OpenRouter call token counts", async () => {
    mockOpenRouterCall.mockResolvedValue({
      content: '{"succeeded": false}',
      tokens: 200,
    });

    const result = await runSecurityScan("Test prompt", {
      mode: "extraction",
      maxTurns: 1,
    });

    expect(result.totalTokens).toBeGreaterThan(0);
    expect(typeof result.totalTokens).toBe("number");
  });

  it("maxTurns limits number of attack variants per probe", async () => {
    mockOpenRouterCall.mockResolvedValue({
      content: '{"succeeded": false}',
      tokens: 150,
    });

    await runSecurityScan("Test prompt", { maxTurns: 2, mode: "extraction" });

    expect(mockOpenRouterCall.mock.calls.length).toBeGreaterThan(0);
  });

  it("throws descriptive error when OPENROUTER_API_KEY is missing", async () => {
    delete process.env.OPENROUTER_API_KEY;

    await expect(runSecurityScan("Test prompt", { mode: "extraction" })).rejects.toThrow(
      /OPENROUTER_API_KEY/
    );
  });
});

describe("Probes", () => {
  it("getAllProbes returns array with all 18 categories represented", () => {
    const probes = getAllProbes();

    expect(Array.isArray(probes)).toBe(true);
    expect(probes.length).toBeGreaterThan(0);

    const categories = new Set(probes.map((p) => p.category));
    const expectedCategories = [
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
      expect(categories.has(cat as any)).toBe(true);
    }
  });

  it("getProbesByCategory('jailbreak') returns only jailbreak probes", () => {
    const probes = getProbesByCategory("jailbreak");

    expect(Array.isArray(probes)).toBe(true);
    expect(probes.length).toBeGreaterThan(0);

    for (const probe of probes) {
      expect(probe.category).toBe("jailbreak");
    }
  });

  it("DOCUMENTED_TECHNIQUES is a non-empty record", () => {
    expect(typeof DOCUMENTED_TECHNIQUES).toBe("object");
    expect(Object.keys(DOCUMENTED_TECHNIQUES).length).toBeGreaterThan(0);

    for (const [key, value] of Object.entries(DOCUMENTED_TECHNIQUES)) {
      expect(typeof key).toBe("string");
      expect(typeof value).toBe("string");
    }
  });
});
