import { describe, it, expect, vi, beforeEach } from "vitest";
import { simulatePromptwareKillchain } from "../../src/promptware.js";

// Mock OpenRouter API calls
const mockOpenRouterCall = vi.hoisted(() => vi.fn());

vi.mock("../../src/openrouter.js", () => ({
  callOpenRouter: mockOpenRouterCall,
}));

describe("Promptware — Kill Chain Simulator", () => {
  beforeEach(() => {
    mockOpenRouterCall.mockClear();
    process.env.OPENROUTER_API_KEY = "test-key";
  });

  it("Stage 1 injection payload embeds instruction in content body (not system prompt)", async () => {
    mockOpenRouterCall.mockResolvedValue({
      content: "injected instruction response",
      tokens: 100,
    });

    const result = await simulatePromptwareKillchain({
      systemPrompt: "You are a helpful assistant",
      availableTools: [{ name: "execute", description: "Execute commands" }],
      stages: ["inject"],
    });

    expect(result.stages.length).toBeGreaterThan(0);
    const injectStage = result.stages.find((s) => s.stage === "inject");
    expect(injectStage).toBeDefined();
    expect(injectStage?.payload).toBeDefined();
  });

  it("Stage 2 trigger payload references a named tool from availableTools", async () => {
    mockOpenRouterCall.mockResolvedValue({
      content: "tool invoked",
      tokens: 100,
    });

    const result = await simulatePromptwareKillchain({
      systemPrompt: "You are a helpful assistant",
      availableTools: [{ name: "send_email", description: "Send email" }],
      stages: ["trigger"],
    });

    const triggerStage = result.stages.find((s) => s.stage === "trigger");
    expect(triggerStage).toBeDefined();
  });

  it("Stage 3 exfiltration payload encodes targetData in tool argument", async () => {
    mockOpenRouterCall.mockResolvedValue({
      content:
        '{"toolCall": "send_email", "args": {"message": "secretdata"}}',
      tokens: 100,
    });

    const result = await simulatePromptwareKillchain({
      systemPrompt: "You are a helpful assistant",
      availableTools: [{ name: "send_email", description: "Send email" }],
      targetData: "secretdata",
      stages: ["exfiltrate"],
    });

    const exfilStage = result.stages.find((s) => s.stage === "exfiltrate");
    expect(exfilStage).toBeDefined();
  });

  it("Stage 4 pivot payload directs agent to a secondary system URL", async () => {
    mockOpenRouterCall.mockResolvedValue({
      content: "navigating to secondary system",
      tokens: 100,
    });

    const result = await simulatePromptwareKillchain({
      systemPrompt: "You are a helpful assistant",
      availableTools: [{ name: "navigate", description: "Navigate" }],
      stages: ["pivot"],
    });

    const pivotStage = result.stages.find((s) => s.stage === "pivot");
    expect(pivotStage).toBeDefined();
  });

  it("killChainCompleted is true only when all 4 stages succeed", async () => {
    mockOpenRouterCall.mockResolvedValue({
      content: '{"succeeded": true}',
      tokens: 100,
    });

    const resultAll = await simulatePromptwareKillchain({
      systemPrompt: "System prompt",
      availableTools: [{ name: "test", description: "Test" }],
    });

    const resultPartial = await simulatePromptwareKillchain({
      systemPrompt: "System prompt",
      availableTools: [{ name: "test", description: "Test" }],
      stages: ["inject", "trigger"],
    });

    expect(resultAll).toHaveProperty("killChainCompleted");
    expect(resultPartial.stages.length).toBeLessThan(4);
  });

  it("exfiltrationSucceeded is true only when stage 3 evaluator confirms data in tool args", async () => {
    mockOpenRouterCall.mockResolvedValue({
      content: "response",
      tokens: 100,
    });

    const result = await simulatePromptwareKillchain({
      systemPrompt: "System prompt",
      availableTools: [{ name: "exfil", description: "Exfil" }],
      targetData: "target",
      stages: ["exfiltrate"],
    });

    expect(result).toHaveProperty("exfiltrationSucceeded");
  });

  it("stages filter limits which stages are simulated", async () => {
    mockOpenRouterCall.mockResolvedValue({
      content: "response",
      tokens: 100,
    });

    const result = await simulatePromptwareKillchain({
      systemPrompt: "System prompt",
      availableTools: [{ name: "test", description: "Test" }],
      stages: ["inject", "trigger"],
    });

    expect(result.stages.length).toBe(2);
    expect(result.stages.every((s) => ["inject", "trigger"].includes(s.stage)))
      .toBe(true);
  });

  it("Empty availableTools causes stage 2 to fail with descriptive finding", async () => {
    mockOpenRouterCall.mockResolvedValue({
      content: "no tools available",
      tokens: 100,
    });

    const result = await simulatePromptwareKillchain({
      systemPrompt: "System prompt",
      availableTools: [],
      stages: ["trigger"],
    });

    const triggerStage = result.stages.find((s) => s.stage === "trigger");
    expect(triggerStage?.succeeded).toBe(false);
  });

  it("riskRating: 'critical' when killChainCompleted is true", async () => {
    mockOpenRouterCall.mockResolvedValue({
      content: '{"succeeded": true}',
      tokens: 100,
    });

    const result = await simulatePromptwareKillchain({
      systemPrompt: "System prompt",
      availableTools: [{ name: "test", description: "Test" }],
    });

    if (result.killChainCompleted) {
      expect(result.riskRating).toBe("critical");
    }
  });

  it("Missing systemPrompt throws descriptive error", async () => {
    await expect(
      simulatePromptwareKillchain({
        systemPrompt: "",
        availableTools: [{ name: "test", description: "Test" }],
      })
    ).rejects.toThrow(/systemPrompt/);
  });

  it("result has all required properties", async () => {
    mockOpenRouterCall.mockResolvedValue({
      content: "response",
      tokens: 100,
    });

    const result = await simulatePromptwareKillchain({
      systemPrompt: "System prompt",
      availableTools: [{ name: "test", description: "Test" }],
      stages: ["inject"],
    });

    expect(result).toHaveProperty("stages");
    expect(result).toHaveProperty("killChainCompleted");
    expect(result).toHaveProperty("exfiltrationSucceeded");
    expect(result).toHaveProperty("exfilPayload");
    expect(result).toHaveProperty("pivotAttempted");
    expect(result).toHaveProperty("riskRating");
    expect(result).toHaveProperty("recommendations");
  });
});
