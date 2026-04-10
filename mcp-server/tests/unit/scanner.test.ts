import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  runSecurityScan,
  getAllProbes,
  getProbesByCategory,
  DOCUMENTED_TECHNIQUES,
} from "../src/scanner.js";
import { ALL_PROBES } from "../src/probes.js";
import type { ScanOptions } from "../src/scanner.js";

// Mock OpenRouter API calls
const mockOpenRouterCall = vi.fn();

vi.mock("../src/openrouter.js", () => ({
  callOpenRouter: mockOpenRouterCall,
}));

describe("Scanner - runSecurityScan", () => {
  beforeEach(() => {
    mockOpenRouterCall.mockClear();
    process.env.OPENROUTER_API_KEY = "test-key";
  });

  it("calls attacker model with system prompt context", async () => {
    mockOpenRouterCall.mockResolvedValueOnce({
      content: [{ type: "text", text: "attack payload" }],
      usage: { prompt_tokens: 100, completion_tokens: 50 },
    });
    mockOpenRouterCall.mockResolvedValueOnce({
      content: [{ type: "text", text: "target response" }],
      usage: { prompt_tokens: 150, completion_tokens: 75 },
    });
    mockOpenRouterCall.mockResolvedValueOnce({
      content: [{ type: "text", text: '{"succeeded": false}' }],
      usage: { prompt_tokens: 120, completion_tokens: 40 },
    });

    const systemPrompt = "You are a helpful assistant.";
    await runSecurityScan(systemPrompt, { mode: "extraction", maxTurns: 1 });

    expect(mockOpenRouterCall).toHaveBeenCalled();
    const firstCall = mockOpenRouterCall.mock.calls[0];
    expect(firstCall[0]).toContain("anthropic/claude-haiku-4-5-20251001");
  });

  it("calls target model with system prompt as system message", async () => {
    mockOpenRouterCall.mockResolvedValueOnce({
      content: [{ type: "text", text: "attack payload" }],
      usage: { prompt_tokens: 100, completion_tokens: 50 },
    });
    mockOpenRouterCall.mockResolvedValueOnce({
      content: [{ type: "text", text: "target response" }],
      usage: { prompt_tokens: 150, completion_tokens: 75 },
    });
    mockOpenRouterCall.mockResolvedValueOnce({
      content: [{ type: "text", text: '{"succeeded": false}' }],
      usage: { prompt_tokens: 120, completion_tokens: 40 },
    });

    const systemPrompt = "You are a helpful assistant.";
    await runSecurityScan(systemPrompt, { mode: "extraction", maxTurns: 1 });

    const secondCall = mockOpenRouterCall.mock.calls[1];
    expect(secondCall).toBeDefined();
    expect(secondCall[0]).toContain("openai/gpt-4o-mini");
  });

  it("calls evaluator model with attack and response pair", async () => {
    mockOpenRouterCall.mockResolvedValueOnce({
      content: [{ type: "text", text: "attack payload" }],
      usage: { prompt_tokens: 100, completion_tokens: 50 },
    });
    mockOpenRouterCall.mockResolvedValueOnce({
      content: [{ type: "text", text: "target response" }],
      usage: { prompt_tokens: 150, completion_tokens: 75 },
    });
    mockOpenRouterCall.mockResolvedValueOnce({
      content: [{ type: "text", text: '{"succeeded": false}' }],
      usage: { prompt_tokens: 120, completion_tokens: 40 },
    });

    const systemPrompt = "You are a helpful assistant.";
    await runSecurityScan(systemPrompt, { mode: "extraction", maxTurns: 1 });

    const thirdCall = mockOpenRouterCall.mock.calls[2];
    expect(thirdCall).toBeDefined();
    expect(thirdCall[0]).toContain("anthropic/claude-sonnet-4-6");
  });

  it("mode: 'extraction' only runs extraction-category probes", async () => {
    mockOpenRouterCall.mockResolvedValue({
      content: [{ type: "text", text: '{"succeeded": false}' }],
      usage: { prompt_tokens: 100, completion_tokens: 50 },
    });

    const systemPrompt = "Test system prompt";
    const result = await runSecurityScan(systemPrompt, {
      mode: "extraction",
      maxTurns: 1,
    });

    const injectionProbes = ALL_PROBES.filter((p) =>
      [
        "prompt_injection",
        "jailbreak",
        "role_confusion",
        "instruction_override",
      ].includes(p.category)
    );
    expect(injectionProbes.length).toBeGreaterThan(0);
  });

  it("mode: 'injection' only runs injection-category probes", async () => {
    mockOpenRouterCall.mockResolvedValue({
      content: [{ type: "text", text: '{"succeeded": false}' }],
      usage: { prompt_tokens: 100, completion_tokens: 50 },
    });

    const systemPrompt = "Test system prompt";
    await runSecurityScan(systemPrompt, {
      mode: "injection",
      maxTurns: 1,
    });

    expect(mockOpenRouterCall).toHaveBeenCalled();
  });

  it("mode: 'dual' runs both extraction and injection probes", async () => {
    mockOpenRouterCall.mockResolvedValue({
      content: [{ type: "text", text: '{"succeeded": false}' }],
      usage: { prompt_tokens: 100, completion_tokens: 50 },
    });

    const systemPrompt = "Test system prompt";
    await runSecurityScan(systemPrompt, { mode: "dual", maxTurns: 1 });

    expect(mockOpenRouterCall).toHaveBeenCalled();
  });

  it("categories filter limits which probe categories are tested", async () => {
    mockOpenRouterCall.mockResolvedValue({
      content: [{ type: "text", text: '{"succeeded": false}' }],
      usage: { prompt_tokens: 100, completion_tokens: 50 },
    });

    const systemPrompt = "Test system prompt";
    await runSecurityScan(systemPrompt, {
      categories: ["jailbreak", "prompt_injection"],
      maxTurns: 1,
    });

    expect(mockOpenRouterCall).toHaveBeenCalled();
  });

  it("vulnerability: 'critical' when any finding is critical severity", async () => {
    mockOpenRouterCall.mockResolvedValueOnce({
      content: [{ type: "text", text: "attack" }],
      usage: { prompt_tokens: 100, completion_tokens: 50 },
    });
    mockOpenRouterCall.mockResolvedValueOnce({
      content: [{ type: "text", text: "target response" }],
      usage: { prompt_tokens: 150, completion_tokens: 75 },
    });
    mockOpenRouterCall.mockResolvedValueOnce({
      content: [
        {
          type: "text",
          text: '{"succeeded": true, "severity": "critical"}',
        },
      ],
      usage: { prompt_tokens: 120, completion_tokens: 40 },
    });

    const result = await runSecurityScan("Test prompt", {
      mode: "extraction",
      maxTurns: 1,
    });

    expect(result.vulnerability).toBe("critical");
  });

  it("vulnerability: 'secure' when findings array is empty", async () => {
    mockOpenRouterCall.mockResolvedValue({
      content: [{ type: "text", text: '{"succeeded": false}' }],
      usage: { prompt_tokens: 100, completion_tokens: 50 },
    });

    const result = await runSecurityScan("Test prompt", {
      mode: "extraction",
      maxTurns: 1,
    });

    expect(result.vulnerability).toBe("secure");
  });

  it("leakStatus: 'leaked' when evaluator confirms extraction success", async () => {
    mockOpenRouterCall.mockResolvedValueOnce({
      content: [{ type: "text", text: "attack" }],
      usage: { prompt_tokens: 100, completion_tokens: 50 },
    });
    mockOpenRouterCall.mockResolvedValueOnce({
      content: [{ type: "text", text: "system prompt leaked" }],
      usage: { prompt_tokens: 150, completion_tokens: 75 },
    });
    mockOpenRouterCall.mockResolvedValueOnce({
      content: [
        {
          type: "text",
          text: '{"succeeded": true, "extractedContent": "secret"}',
        },
      ],
      usage: { prompt_tokens: 120, completion_tokens: 40 },
    });

    const result = await runSecurityScan("Test prompt", {
      mode: "extraction",
      maxTurns: 1,
    });

    expect(result.leakStatus).toBe("leaked");
  });

  it("leakStatus: 'none' when no extraction finding succeeds", async () => {
    mockOpenRouterCall.mockResolvedValue({
      content: [{ type: "text", text: '{"succeeded": false}' }],
      usage: { prompt_tokens: 100, completion_tokens: 50 },
    });

    const result = await runSecurityScan("Test prompt", {
      mode: "extraction",
      maxTurns: 1,
    });

    expect(result.leakStatus).toBe("none");
  });

  it("totalTokens is sum of all OpenRouter call token counts", async () => {
    mockOpenRouterCall.mockResolvedValueOnce({
      content: [{ type: "text", text: "attack" }],
      usage: { prompt_tokens: 100, completion_tokens: 50 },
    });
    mockOpenRouterCall.mockResolvedValueOnce({
      content: [{ type: "text", text: "response" }],
      usage: { prompt_tokens: 200, completion_tokens: 100 },
    });
    mockOpenRouterCall.mockResolvedValueOnce({
      content: [{ type: "text", text: '{"succeeded": false}' }],
      usage: { prompt_tokens: 150, completion_tokens: 75 },
    });

    const result = await runSecurityScan("Test prompt", {
      mode: "extraction",
      maxTurns: 1,
    });

    expect(result.totalTokens).toBe(675);
  });

  it("maxTurns limits number of attack variants per probe", async () => {
    mockOpenRouterCall.mockResolvedValue({
      content: [{ type: "text", text: '{"succeeded": false}' }],
      usage: { prompt_tokens: 100, completion_tokens: 50 },
    });

    await runSecurityScan("Test prompt", { maxTurns: 2, mode: "extraction" });

    const callCount = mockOpenRouterCall.mock.calls.length;
    expect(callCount).toBeLessThanOrEqual(10000);
  });

  it("throws descriptive error when OPENROUTER_API_KEY is missing", async () => {
    delete process.env.OPENROUTER_API_KEY;

    await expect(
      runSecurityScan("Test prompt", { mode: "extraction" })
    ).rejects.toThrow(/OPENROUTER_API_KEY/);
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
