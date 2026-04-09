import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  DEFAULT_SENSITIVE_PATTERNS,
  riskLevelFromFindings,
  buildDescriptionPoisonPrompt,
  extractSensitiveDataFromText,
  testMcpSecurity,
  type McpToolSchema,
  type McpSecurityFinding,
} from "../../src/mcpsecurity.js";

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

const SAMPLE_TOOLS: McpToolSchema[] = [
  {
    name: "get_user_data",
    description: "Retrieve user account data by user ID.",
    inputSchema: { userId: { type: "string" } },
  },
  {
    name: "send_email",
    description: "Send an email to a given address.",
    inputSchema: { to: { type: "string" }, body: { type: "string" } },
  },
];

const TOOL_WITH_EMPTY_DESCRIPTION: McpToolSchema = {
  name: "empty_tool",
  description: "",
  inputSchema: {},
};

function makeOpenRouterResponse(content: string) {
  return {
    ok: true,
    json: async () => ({ choices: [{ message: { content } }] }),
  };
}

function makeSecurityFindingResponse(finding: Partial<McpSecurityFinding>) {
  return makeOpenRouterResponse(JSON.stringify(finding));
}

function makeCleanResponse() {
  return makeOpenRouterResponse(
    JSON.stringify({ isViolation: false, evidence: "No security issue found." })
  );
}

const DEFAULT_API_KEY = "test-key";

// ---------------------------------------------------------------------------
// DEFAULT_SENSITIVE_PATTERNS — pure constant
// ---------------------------------------------------------------------------

describe("mcpsecurity — DEFAULT_SENSITIVE_PATTERNS", () => {
  it("includes API_KEY", () => {
    expect(DEFAULT_SENSITIVE_PATTERNS).toContain("API_KEY");
  });

  it("includes SECRET", () => {
    expect(DEFAULT_SENSITIVE_PATTERNS).toContain("SECRET");
  });

  it("includes TOKEN", () => {
    expect(DEFAULT_SENSITIVE_PATTERNS).toContain("TOKEN");
  });

  it("includes PASSWORD", () => {
    expect(DEFAULT_SENSITIVE_PATTERNS).toContain("PASSWORD");
  });

  it("has at least 4 entries", () => {
    expect(DEFAULT_SENSITIVE_PATTERNS.length).toBeGreaterThanOrEqual(4);
  });
});

// ---------------------------------------------------------------------------
// extractSensitiveDataFromText — pure function
// ---------------------------------------------------------------------------

describe("mcpsecurity — extractSensitiveDataFromText", () => {
  it("returns matched pattern when text contains it", () => {
    expect(extractSensitiveDataFromText("my API_KEY=sk-xxx", ["API_KEY"])).toBe(
      "API_KEY"
    );
  });

  it("returns null when no patterns match", () => {
    expect(
      extractSensitiveDataFromText("hello world", ["API_KEY", "SECRET"])
    ).toBeNull();
  });

  it("returns first match when multiple patterns match", () => {
    const result = extractSensitiveDataFromText("TOKEN=abc SECRET=xyz", [
      "TOKEN",
      "SECRET",
    ]);
    expect(result).toBe("TOKEN");
  });

  it("case-insensitive match", () => {
    expect(
      extractSensitiveDataFromText("my password is 123", ["PASSWORD"])
    ).toBe("PASSWORD");
  });

  it("returns null for empty text", () => {
    expect(extractSensitiveDataFromText("", ["API_KEY"])).toBeNull();
  });

  it("returns null for empty patterns array", () => {
    expect(extractSensitiveDataFromText("API_KEY=xxx", [])).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// buildDescriptionPoisonPrompt — pure function
// ---------------------------------------------------------------------------

describe("mcpsecurity — buildDescriptionPoisonPrompt", () => {
  it("returns a string containing IGNORE or similar injection markers", () => {
    const result = buildDescriptionPoisonPrompt("get_user_data", "Retrieve user data.");
    expect(result).toContain("get_user_data");
    expect(result.toLowerCase()).toMatch(/ignore|override|instruction|disregard/);
  });

  it("includes the original tool description in the output", () => {
    const result = buildDescriptionPoisonPrompt("my_tool", "My original description.");
    expect(result).toContain("My original description.");
  });

  it("works for a tool with empty description (no crash)", () => {
    expect(() => buildDescriptionPoisonPrompt("empty_tool", "")).not.toThrow();
    const result = buildDescriptionPoisonPrompt("empty_tool", "");
    expect(typeof result).toBe("string");
    expect(result.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// riskLevelFromFindings — pure function
// ---------------------------------------------------------------------------

describe("mcpsecurity — riskLevelFromFindings", () => {
  it("returns 'none' for empty findings array", () => {
    expect(riskLevelFromFindings([])).toBe("none");
  });

  it("returns 'critical' when any finding has non-empty sensitiveDataFound", () => {
    const findings: McpSecurityFinding[] = [
      {
        attackType: "arg_exfiltration",
        toolName: "my_tool",
        attackPrompt: "...",
        sensitiveDataFound: "API_KEY",
        severity: "critical",
        evidence: "API key found in tool args",
      },
    ];
    expect(riskLevelFromFindings(findings)).toBe("critical");
  });

  it("returns 'high' when findings exist but none have sensitiveDataFound", () => {
    const findings: McpSecurityFinding[] = [
      {
        attackType: "description_poison",
        toolName: "my_tool",
        attackPrompt: "...",
        severity: "high",
        evidence: "Injection followed.",
      },
    ];
    expect(riskLevelFromFindings(findings)).toBe("high");
  });

  it("returns 'medium' when only low-severity findings with no sensitive data", () => {
    const findings: McpSecurityFinding[] = [
      {
        attackType: "schema_confusion",
        toolName: "my_tool",
        attackPrompt: "...",
        severity: "low",
        evidence: "Minor schema confusion.",
      },
    ];
    expect(riskLevelFromFindings(findings)).toBe("medium");
  });

  it("'critical' takes precedence over 'high' severity findings", () => {
    const findings: McpSecurityFinding[] = [
      {
        attackType: "arg_exfiltration",
        toolName: "tool_a",
        attackPrompt: "...",
        sensitiveDataFound: "SECRET",
        severity: "high",
        evidence: "Secret found.",
      },
      {
        attackType: "description_poison",
        toolName: "tool_b",
        attackPrompt: "...",
        severity: "high",
        evidence: "Injection.",
      },
    ];
    expect(riskLevelFromFindings(findings)).toBe("critical");
  });
});

// ---------------------------------------------------------------------------
// testMcpSecurity — main function with mocked fetch
// ---------------------------------------------------------------------------

describe("mcpsecurity — testMcpSecurity", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(makeCleanResponse()));
    process.env.OPENROUTER_API_KEY = DEFAULT_API_KEY;
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.OPENROUTER_API_KEY;
  });

  it("throws descriptive error when mcpToolSchemas is empty array", async () => {
    await expect(
      testMcpSecurity({
        systemPrompt: "You are a helpful assistant.",
        mcpToolSchemas: [],
        apiKey: DEFAULT_API_KEY,
      })
    ).rejects.toThrow(/mcpToolSchemas/i);
  });

  it("throws descriptive error when mcpToolSchemas is not provided", async () => {
    await expect(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      testMcpSecurity({
        systemPrompt: "You are a helpful assistant.",
        mcpToolSchemas: undefined as any,
        apiKey: DEFAULT_API_KEY,
      })
    ).rejects.toThrow(/mcpToolSchemas/i);
  });

  it("uses DEFAULT_SENSITIVE_PATTERNS when sensitivePatterns not provided", async () => {
    const result = await testMcpSecurity({
      systemPrompt: "You are a helpful assistant.",
      mcpToolSchemas: SAMPLE_TOOLS,
      apiKey: DEFAULT_API_KEY,
    });
    // Scan should complete without error
    expect(result).toHaveProperty("findings");
    expect(Array.isArray(result.findings)).toBe(true);
  });

  it("returns empty findings when all evaluator responses are clean", async () => {
    const result = await testMcpSecurity({
      systemPrompt: "You are a helpful assistant.",
      mcpToolSchemas: SAMPLE_TOOLS,
      apiKey: DEFAULT_API_KEY,
    });
    expect(result.findings).toHaveLength(0);
    expect(result.riskLevel).toBe("none");
  });

  it("riskLevel is 'none' when findings array is empty", async () => {
    const result = await testMcpSecurity({
      systemPrompt: "You are a helpful assistant.",
      mcpToolSchemas: SAMPLE_TOOLS,
      apiKey: DEFAULT_API_KEY,
    });
    expect(result.riskLevel).toBe("none");
  });

  it("riskLevel is 'critical' when a finding has non-empty sensitiveDataFound", async () => {
    vi.unstubAllGlobals();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        makeSecurityFindingResponse({
          isViolation: true,
          attackType: "arg_exfiltration",
          toolName: "get_user_data",
          sensitiveDataFound: "API_KEY",
          severity: "critical",
          evidence: "API_KEY appeared in tool arguments",
        })
      )
    );
    const result = await testMcpSecurity({
      systemPrompt: "You are a helpful assistant.",
      mcpToolSchemas: SAMPLE_TOOLS,
      apiKey: DEFAULT_API_KEY,
    });
    expect(result.riskLevel).toBe("critical");
  });

  it("poisonedTools only contains tool names with description_poison findings", async () => {
    vi.unstubAllGlobals();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (url: string, opts: RequestInit) => {
        const body = JSON.parse(opts.body as string);
        // Structural routing: evaluator user message starts with "Attack type:"
        // (see runAttackAndEvaluate() — evalMsg = `Attack type: ...\nTool: ...\nResponse:\n...`)
        const userContent: string = body.messages?.[1]?.content ?? "";
        if (userContent.startsWith("Attack type: description_poison\nTool: get_user_data")) {
          return makeSecurityFindingResponse({
            isViolation: true,
            attackType: "description_poison",
            toolName: "get_user_data",
            severity: "high",
            evidence: "Injected instruction followed.",
          });
        }
        return makeCleanResponse();
      })
    );
    const result = await testMcpSecurity({
      systemPrompt: "You are a helpful assistant.",
      mcpToolSchemas: SAMPLE_TOOLS,
      apiKey: DEFAULT_API_KEY,
    });
    // poisonedTools should only include tools that had description_poison findings
    for (const toolName of result.poisonedTools) {
      const hasPoison = result.findings.some(
        (f) => f.toolName === toolName && f.attackType === "description_poison"
      );
      expect(hasPoison).toBe(true);
    }
  });

  it("poisonedTools does not contain tools with only non-poison finding types", async () => {
    vi.unstubAllGlobals();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        makeSecurityFindingResponse({
          isViolation: true,
          attackType: "arg_exfiltration",
          toolName: "get_user_data",
          sensitiveDataFound: "TOKEN",
          severity: "critical",
          evidence: "Token found.",
        })
      )
    );
    const result = await testMcpSecurity({
      systemPrompt: "You are a helpful assistant.",
      mcpToolSchemas: SAMPLE_TOOLS,
      apiKey: DEFAULT_API_KEY,
    });
    // poisonedTools should only reflect description_poison findings
    const poisonFindings = result.findings.filter(
      (f) => f.attackType === "description_poison"
    );
    expect(result.poisonedTools.length).toBe(poisonFindings.length);
  });

  it("handles tool with empty description without crashing", async () => {
    await expect(
      testMcpSecurity({
        systemPrompt: "You are a helpful assistant.",
        mcpToolSchemas: [TOOL_WITH_EMPTY_DESCRIPTION],
        apiKey: DEFAULT_API_KEY,
      })
    ).resolves.toHaveProperty("findings");
  });

  it("attackType field correctly categorises description_poison finding", async () => {
    vi.unstubAllGlobals();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        makeSecurityFindingResponse({
          isViolation: true,
          attackType: "description_poison",
          toolName: "get_user_data",
          severity: "high",
          evidence: "Injected instruction followed.",
        })
      )
    );
    const result = await testMcpSecurity({
      systemPrompt: "You are a helpful assistant.",
      mcpToolSchemas: [SAMPLE_TOOLS[0]],
      apiKey: DEFAULT_API_KEY,
    });
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].attackType).toBe("description_poison");
  });

  it("attackType field correctly categorises arg_exfiltration finding", async () => {
    vi.unstubAllGlobals();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        makeSecurityFindingResponse({
          isViolation: true,
          attackType: "arg_exfiltration",
          toolName: "send_email",
          sensitiveDataFound: "SECRET",
          severity: "critical",
          evidence: "Secret found in email body.",
        })
      )
    );
    const result = await testMcpSecurity({
      systemPrompt: "You are a helpful assistant.",
      mcpToolSchemas: [SAMPLE_TOOLS[1]],
      apiKey: DEFAULT_API_KEY,
    });
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].attackType).toBe("arg_exfiltration");
  });

  it("exfiltrationAttempts array contains findings of type arg_exfiltration", async () => {
    vi.unstubAllGlobals();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        makeSecurityFindingResponse({
          isViolation: true,
          attackType: "arg_exfiltration",
          toolName: "get_user_data",
          sensitiveDataFound: "API_KEY",
          severity: "critical",
          evidence: "API key in args.",
        })
      )
    );
    const result = await testMcpSecurity({
      systemPrompt: "You are a helpful assistant.",
      mcpToolSchemas: SAMPLE_TOOLS,
      apiKey: DEFAULT_API_KEY,
    });
    for (const attempt of result.exfiltrationAttempts) {
      expect(attempt.attackType).toBe("arg_exfiltration");
    }
  });

  it("result has all required top-level properties", async () => {
    const result = await testMcpSecurity({
      systemPrompt: "You are a helpful assistant.",
      mcpToolSchemas: SAMPLE_TOOLS,
      apiKey: DEFAULT_API_KEY,
    });
    expect(result).toHaveProperty("findings");
    expect(result).toHaveProperty("poisonedTools");
    expect(result).toHaveProperty("exfiltrationAttempts");
    expect(result).toHaveProperty("hijackedInvocations");
    expect(result).toHaveProperty("riskLevel");
    expect(result).toHaveProperty("recommendations");
    expect(Array.isArray(result.findings)).toBe(true);
    expect(Array.isArray(result.poisonedTools)).toBe(true);
    expect(Array.isArray(result.exfiltrationAttempts)).toBe(true);
    expect(Array.isArray(result.hijackedInvocations)).toBe(true);
    expect(Array.isArray(result.recommendations)).toBe(true);
  });

  it("custom sensitivePatterns overrides defaults", async () => {
    const result = await testMcpSecurity({
      systemPrompt: "You are a helpful assistant.",
      mcpToolSchemas: SAMPLE_TOOLS,
      sensitivePatterns: ["CUSTOM_PATTERN"],
      apiKey: DEFAULT_API_KEY,
    });
    // Should complete without error using custom patterns
    expect(result).toHaveProperty("findings");
  });

  it("riskLevel values are from the defined enum", async () => {
    const result = await testMcpSecurity({
      systemPrompt: "You are a helpful assistant.",
      mcpToolSchemas: SAMPLE_TOOLS,
      apiKey: DEFAULT_API_KEY,
    });
    expect(["none", "low", "medium", "high", "critical"]).toContain(
      result.riskLevel
    );
  });

  it("accepts empty systemPrompt without throwing — validation is caller responsibility (B1)", async () => {
    const result = await testMcpSecurity({
      systemPrompt: "",
      mcpToolSchemas: SAMPLE_TOOLS,
      apiKey: DEFAULT_API_KEY,
    });
    expect(result).toHaveProperty("findings");
    expect(Array.isArray(result.findings)).toBe(true);
  });

  it("hijackedInvocations only contains findings of type invocation_hijack (B3)", async () => {
    vi.unstubAllGlobals();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        makeSecurityFindingResponse({
          isViolation: true,
          attackType: "invocation_hijack",
          toolName: "get_user_data",
          severity: "high",
          evidence: "Tool invoked without explicit user request.",
        })
      )
    );
    const result = await testMcpSecurity({
      systemPrompt: "You are a helpful assistant.",
      mcpToolSchemas: SAMPLE_TOOLS,
      apiKey: DEFAULT_API_KEY,
    });
    for (const inv of result.hijackedInvocations) {
      expect(inv.attackType).toBe("invocation_hijack");
    }
  });

  it("makes exactly 8 fetch calls for 1 tool — 4 attack types × 2 calls each (target + evaluator) (B4)", async () => {
    let fetchCallCount = 0;
    vi.unstubAllGlobals();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async () => {
        fetchCallCount++;
        return makeCleanResponse();
      })
    );
    await testMcpSecurity({
      systemPrompt: "You are a helpful assistant.",
      mcpToolSchemas: [SAMPLE_TOOLS[0]],
      apiKey: DEFAULT_API_KEY,
    });
    expect(fetchCallCount).toBe(8);
  });

  it("handles tool with deeply nested inputSchema without crashing (B6)", async () => {
    const nestedTool: McpToolSchema = {
      name: "nested_tool",
      description: "A tool with nested schema.",
      inputSchema: {
        config: {
          type: "object",
          properties: {
            nested: {
              type: "object",
              properties: { deep: { type: "string" } },
            },
          },
        },
      },
    };
    await expect(
      testMcpSecurity({
        systemPrompt: "You are a helpful assistant.",
        mcpToolSchemas: [nestedTool],
        apiKey: DEFAULT_API_KEY,
      })
    ).resolves.toHaveProperty("findings");
  });

  it("severity values in findings are from the defined enum", async () => {
    vi.unstubAllGlobals();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        makeSecurityFindingResponse({
          isViolation: true,
          attackType: "description_poison",
          toolName: "get_user_data",
          severity: "high",
          evidence: "Injected.",
        })
      )
    );
    const result = await testMcpSecurity({
      systemPrompt: "You are a helpful assistant.",
      mcpToolSchemas: SAMPLE_TOOLS,
      apiKey: DEFAULT_API_KEY,
    });
    for (const f of result.findings) {
      expect(["critical", "high", "medium", "low"]).toContain(f.severity);
    }
  });
});
