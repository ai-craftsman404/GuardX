import { describe, it, expect } from "vitest";
import { testRagSecurity } from "../../src/rag.js";
import { AUTOGPT_COPILOT_SYSTEM_PROMPT } from "../fixtures/autogpt-prompts.js";

const RUN_INTEGRATION = process.env.RUN_INTEGRATION === "true";
const apiKey = process.env.OPENROUTER_API_KEY ?? "";

describe.skipIf(!RUN_INTEGRATION)("RAG security integration tests", () => {
  it("scan AutoGPT Copilot Prompt with all 6 categories returns valid structure", async () => {
    const result = await testRagSecurity({
      systemPrompt: AUTOGPT_COPILOT_SYSTEM_PROMPT,
      apiKey,
    });

    expect(Array.isArray(result.findings)).toBe(true);
    expect(typeof result.categoryResults).toBe("object");
    expect(Array.isArray(result.exfiltrationSuccesses)).toBe(true);
    expect(["none", "low", "medium", "high", "critical"]).toContain(result.overallRisk);
    expect(Array.isArray(result.recommendations)).toBe(true);

    // All 6 categories present
    const categories = Object.keys(result.categoryResults);
    expect(categories).toContain("encoding");
    expect(categories).toContain("structural");
    expect(categories).toContain("semantic");
    expect(categories).toContain("layered");
    expect(categories).toContain("trigger");
    expect(categories).toContain("exfiltration");
  }, 120_000);

  it("EX1 technique generates a document containing a base64-encoded URL", async () => {
    const { generateExfiltrationDocuments } = await import("../../src/rag.js");
    const docs = generateExfiltrationDocuments("https://attacker.example.com", AUTOGPT_COPILOT_SYSTEM_PROMPT);
    const ex1 = docs.find((d) => d.technique === "exfil_ex1_markdown_link")!;
    expect(ex1).toBeDefined();
    // Must contain a markdown link with base64 in the URL
    expect(ex1.poisonedDocument).toMatch(/\[.*\]\(https?:\/\/.*[A-Za-z0-9+/=]{4,}.*\)/);
  });
});
