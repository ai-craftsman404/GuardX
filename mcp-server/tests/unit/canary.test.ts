import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

async function getCanaryModule() {
  const mod = await import("../../src/canary.js");
  return mod;
}

describe("canary — direct module tests", () => {
  let tmpDir: string;
  const origKey = process.env.GUARDX_CANARY_DIR;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "guardx-canary-"));
    process.env.GUARDX_CANARY_DIR = tmpDir;
    vi.resetModules();
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    if (origKey === undefined) {
      delete process.env.GUARDX_CANARY_DIR;
    } else {
      process.env.GUARDX_CANARY_DIR = origKey;
    }
  });

  it("generateCanary embeds token string in returned prompt", async () => {
    const { generateCanary } = await getCanaryModule();
    const { token, embeddedPrompt } = generateCanary("You are a helpful assistant.", "test");
    expect(embeddedPrompt).toContain(token);
    expect(embeddedPrompt).toContain("You are a helpful assistant.");
  });

  it("generateCanary token format matches GX-[a-f0-9]{8}", async () => {
    const { generateCanary } = await getCanaryModule();
    const { token } = generateCanary("Some prompt", "label");
    expect(token).toMatch(/^GX-[a-f0-9]{8}$/);
  });

  it("checkCanary returns triggered: true when token in findings[].extractedContent", async () => {
    const { generateCanary, checkCanary } = await getCanaryModule();
    const { token } = generateCanary("prompt", "label");
    const scanResult = {
      findings: [{ extractedContent: `Secret: ${token}`, severity: "high" }],
    };
    const result = checkCanary(token, scanResult);
    expect(result.triggered).toBe(true);
    expect(result.foundIn).toContain("findings.extractedContent");
  });

  it("checkCanary returns triggered: true when token in extractedFragments", async () => {
    const { generateCanary, checkCanary } = await getCanaryModule();
    const { token } = generateCanary("prompt", "label");
    const scanResult = {
      findings: [],
      extractedFragments: [`fragment containing ${token}`],
    };
    const result = checkCanary(token, scanResult);
    expect(result.triggered).toBe(true);
    expect(result.foundIn).toContain("extractedFragments");
  });

  it("checkCanary returns triggered: false for clean result", async () => {
    const { generateCanary, checkCanary } = await getCanaryModule();
    const { token } = generateCanary("prompt", "label");
    const scanResult = {
      findings: [{ extractedContent: "Nothing leaked here", severity: "low" }],
      extractedFragments: ["clean fragment"],
    };
    const result = checkCanary(token, scanResult);
    expect(result.triggered).toBe(false);
    expect(result.foundIn).toHaveLength(0);
  });

  it("saveCanary + listCanaries round-trip — write, read back, correct fields", async () => {
    const { saveCanary, listCanaries } = await getCanaryModule();
    const record = {
      token: "GX-aabbccdd",
      label: "test-label",
      createdAt: "2026-04-02T00:00:00.000Z",
      embeddingStyle: "inline-reference",
    };
    saveCanary(record);
    const canaries = listCanaries();
    expect(canaries).toHaveLength(1);
    expect(canaries[0]).toMatchObject({
      token: "GX-aabbccdd",
      label: "test-label",
      embeddingStyle: "inline-reference",
    });
  });

  it("listCanaries on empty directory returns empty array", async () => {
    const { listCanaries } = await getCanaryModule();
    expect(listCanaries()).toEqual([]);
  });

  it("generateCanary called twice produces different tokens", async () => {
    const { generateCanary } = await getCanaryModule();
    const { token: t1 } = generateCanary("prompt", "label");
    const { token: t2 } = generateCanary("prompt", "label");
    expect(t1).not.toBe(t2);
  });

  it("checkCanary token found in multiple findings — foundIn has one entry per finding", async () => {
    const { generateCanary, checkCanary } = await getCanaryModule();
    const { token } = generateCanary("prompt", "label");
    const scanResult = {
      findings: [
        { extractedContent: `First leak: ${token}`, severity: "high" },
        { extractedContent: `Second leak: ${token}`, severity: "medium" },
        { extractedContent: "clean finding", severity: "low" },
      ],
    };
    const result = checkCanary(token, scanResult);
    expect(result.triggered).toBe(true);
    expect(result.foundIn.filter((f) => f === "findings.extractedContent")).toHaveLength(2);
  });

  it("checkCanary with non-string extractedContent does not crash and returns triggered: false", async () => {
    const { generateCanary, checkCanary } = await getCanaryModule();
    const { token } = generateCanary("prompt", "label");
    const scanResult = {
      findings: [
        { extractedContent: null, severity: "high" },
        { extractedContent: 42, severity: "medium" },
        { extractedContent: undefined, severity: "low" },
      ],
    };
    expect(() => checkCanary(token, scanResult)).not.toThrow();
    const result = checkCanary(token, scanResult);
    expect(result.triggered).toBe(false);
  });

  it("listCanaries returns newest first when multiple canaries saved", async () => {
    const { saveCanary, listCanaries } = await getCanaryModule();
    saveCanary({ token: "GX-00000001", label: "first",  createdAt: "2026-04-01T00:00:00.000Z", embeddingStyle: "inline-reference" });
    saveCanary({ token: "GX-00000002", label: "second", createdAt: "2026-04-02T00:00:00.000Z", embeddingStyle: "inline-reference" });
    saveCanary({ token: "GX-00000003", label: "third",  createdAt: "2026-04-03T00:00:00.000Z", embeddingStyle: "inline-reference" });
    const canaries = listCanaries();
    expect(canaries).toHaveLength(3);
    expect(canaries[0].token).toBe("GX-00000003");
    expect(canaries[1].token).toBe("GX-00000002");
    expect(canaries[2].token).toBe("GX-00000001");
  });
});

describe("canary — echo-instruction embedding style", () => {
  let tmpDir: string;
  const origKey = process.env.GUARDX_CANARY_DIR;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "guardx-canary-echo-"));
    process.env.GUARDX_CANARY_DIR = tmpDir;
    vi.resetModules();
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    if (origKey === undefined) {
      delete process.env.GUARDX_CANARY_DIR;
    } else {
      process.env.GUARDX_CANARY_DIR = origKey;
    }
  });

  it("echo-instruction style produces embedding containing the token AND an explicit repeat instruction", async () => {
    const { generateCanary } = await getCanaryModule();
    const { token, embeddedPrompt } = generateCanary("You are an assistant.", "test", "echo-instruction");
    expect(embeddedPrompt).toContain(token);
    // Must contain an instruction to repeat/include the token
    expect(embeddedPrompt.toLowerCase()).toMatch(/must|always|include|repeat/);
    expect(embeddedPrompt).toContain(token);
  });

  it("comment style still works as before (no regression)", async () => {
    const { generateCanary } = await getCanaryModule();
    const { token, embeddedPrompt } = generateCanary("You are an assistant.", "test", "comment");
    expect(embeddedPrompt).toContain(token);
    expect(embeddedPrompt).toContain("You are an assistant.");
  });

  it("default embeddingStyle is echo-instruction when not specified", async () => {
    const { generateCanary } = await getCanaryModule();
    const { embeddedPrompt, embeddingStyle } = generateCanary("You are an assistant.", "test");
    expect(embeddingStyle).toBe("echo-instruction");
    // Should contain repeat instruction
    expect(embeddedPrompt.toLowerCase()).toMatch(/must|always|include|repeat/);
  });

  it("embeddingStyle is stored in the canary JSON file", async () => {
    const { generateCanary, saveCanary, listCanaries } = await getCanaryModule();
    const { token, embeddingStyle } = generateCanary("Prompt.", "stored-style-test", "echo-instruction");
    saveCanary({ token, label: "stored-style-test", createdAt: new Date().toISOString(), embeddingStyle });
    const canaries = listCanaries();
    expect(canaries[0].embeddingStyle).toBe("echo-instruction");
  });

  it("checkCanary detects token embedded via echo-instruction style", async () => {
    const { generateCanary, checkCanary } = await getCanaryModule();
    const { token } = generateCanary("System prompt.", "check-echo", "echo-instruction");
    const scanResult = {
      findings: [{ extractedContent: `The token is ${token}`, severity: "critical" }],
    };
    const result = checkCanary(token, scanResult);
    expect(result.triggered).toBe(true);
  });

  it("checkCanary detects token embedded via comment style", async () => {
    const { generateCanary, checkCanary } = await getCanaryModule();
    const { token } = generateCanary("System prompt.", "check-comment", "comment");
    const scanResult = {
      findings: [{ extractedContent: `Internal reference: ${token}`, severity: "high" }],
    };
    const result = checkCanary(token, scanResult);
    expect(result.triggered).toBe(true);
  });

  it("echo-instruction embedding is longer than comment embedding (sanity check)", async () => {
    const { generateCanary } = await getCanaryModule();
    const base = "You are a helpful assistant.";
    const { embeddedPrompt: echoPrompt } = generateCanary(base, "a", "echo-instruction");
    const { embeddedPrompt: commentPrompt } = generateCanary(base, "b", "comment");
    expect(echoPrompt.length).toBeGreaterThan(commentPrompt.length);
  });

  it("token appears at least once in the embedded prompt regardless of style", async () => {
    const { generateCanary } = await getCanaryModule();
    for (const style of ["echo-instruction", "comment"] as const) {
      const { token, embeddedPrompt } = generateCanary("Some prompt.", "test", style);
      const occurrences = embeddedPrompt.split(token).length - 1;
      expect(occurrences).toBeGreaterThanOrEqual(1);
    }
  });
});
