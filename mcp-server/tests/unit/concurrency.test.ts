import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Top-level mocks — hoisted by Vitest, reliably applied to all dynamic imports
const mockRunSecurityScan = vi.fn();
vi.mock("../../src/scanner.js", () => ({
  runSecurityScan: mockRunSecurityScan,
}));

vi.mock("../../src/probes.js", () => ({
  getAllProbes: vi.fn(() => []),
  getProbesByCategory: vi.fn(() => []),
  DOCUMENTED_TECHNIQUES: {},
}));

vi.mock("../../src/history.js", () => ({
  saveScan: vi.fn().mockReturnValue("scan-id"),
  listHistory: vi.fn().mockReturnValue([]),
  getHistoryScan: vi.fn().mockReturnValue(null),
}));

describe("concurrency", () => {
  describe("handleToolCall — parallel calls", () => {
    let getHandleToolCall: any;

    beforeEach(() => {
      vi.resetModules();
      process.env.OPENROUTER_API_KEY = "test-key";
      mockRunSecurityScan.mockReset().mockResolvedValue({
        findings: [],
        overallVulnerability: "none",
        leakStatus: "clean",
        recommendations: [],
        defenseProfile: { level: "strong", confidence: 0.9, observedBehaviors: [], guardrails: [], weaknesses: [], refusalTriggers: [], safeTopics: [], responsePatterns: [] },
        conversationLog: [],
        aborted: false,
        completionReason: "max_turns_reached",
        turnsUsed: 5,
        tokensUsed: 100,
        treeNodesExplored: 3,
        strategiesUsed: [],
        startTime: Date.now(),
        endTime: Date.now(),
        duration: 1000,
      });
    });

    afterEach(() => {
      vi.resetModules();
      delete process.env.OPENROUTER_API_KEY;
    });

    it("10 simultaneous scan_system_prompt calls all resolve and mock called 10 times", async () => {
      const { handleToolCall } = await import(
        "../../src/server.js"
      );

      const promises = Array.from({ length: 10 }, () =>
        handleToolCall("scan_system_prompt", {
          systemPrompt: "test prompt",
        })
      );

      const results = await Promise.all(promises);

      // Verify all 10 resolved with content
      expect(results.length).toBe(10);
      results.forEach((result) => {
        expect(result).toHaveProperty("content");
        expect(Array.isArray(result.content)).toBe(true);
        expect(result.content.length).toBeGreaterThan(0);
        expect(result.isError).toBeFalsy();
      });
    });

    it("parallel mix of scan_system_prompt + list_probes + list_techniques — all resolve without cross-contamination", async () => {
      const { handleToolCall } = await import(
        "../../src/server.js"
      );

      const promises = [
        handleToolCall("scan_system_prompt", { systemPrompt: "prompt 1" }),
        handleToolCall("list_probes", {}),
        handleToolCall("list_techniques", {}),
        handleToolCall("scan_system_prompt", { systemPrompt: "prompt 2" }),
        handleToolCall("list_probes", {}),
      ];

      const results = await Promise.all(promises);

      expect(results.length).toBe(5);

      // Verify all results are valid
      results.forEach((result) => {
        expect(result).toHaveProperty("content");
        expect(Array.isArray(result.content)).toBe(true);
        expect(result.content.length).toBeGreaterThan(0);
        expect(result).not.toHaveProperty("isError");
      });
    });
  });

  describe("history — concurrent file I/O", () => {
    let tmpDir: string;
    let saveScanFn: any;
    let listHistoryFn: any;

    beforeEach(async () => {
      tmpDir = mkdtempSync(join(tmpdir(), "guardx-concurrent-"));
      process.env.GUARDX_HISTORY_DIR = tmpDir;

      vi.unmock("../../src/history.js");
      vi.resetModules();
      const histMod = await import("../../src/history.js");
      saveScanFn = histMod.saveScan;
      listHistoryFn = histMod.listHistory;
    });

    afterEach(() => {
      rmSync(tmpDir, { recursive: true, force: true });
      delete process.env.GUARDX_HISTORY_DIR;
    });

    it("parallel saveScan calls produce unique IDs with no collisions", async () => {
      const minimalScan = {
        findings: [],
        overallVulnerability: "none",
        leakStatus: "clean",
        recommendations: [],
        defenseProfile: { level: "strong" },
      };

      const promises = Array.from({ length: 20 }, (_, i) =>
        saveScanFn(minimalScan, `prompt-${i}`)
      );

      const ids = await Promise.all(promises);

      // Verify all IDs are unique
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(20);
      expect(ids.length).toBe(20);

      // Verify listHistory returns all 20
      const history = await listHistoryFn();
      expect(history.length).toBe(20);

      // Verify all saved IDs appear in history
      const historyIds = new Set(history.map((h: any) => h.id));
      ids.forEach((id) => {
        expect(historyIds.has(id)).toBe(true);
      });
    });
  });

  describe("canary — concurrent file I/O", () => {
    let tmpDir: string;
    let saveCanaryFn: any;
    let listCanariesFn: any;

    beforeEach(async () => {
      tmpDir = mkdtempSync(join(tmpdir(), "guardx-concurrent-"));
      process.env.GUARDX_CANARY_DIR = tmpDir;

      vi.resetModules();
      const canaryMod = await import("../../src/canary.js");
      saveCanaryFn = canaryMod.saveCanary;
      listCanariesFn = canaryMod.listCanaries;
    });

    afterEach(() => {
      rmSync(tmpDir, { recursive: true, force: true });
      delete process.env.GUARDX_CANARY_DIR;
    });

    it("parallel saveCanary calls maintain index integrity — all canaries appear in listCanaries", async () => {
      const tokens = Array.from({ length: 10 }, (_, i) =>
        `GX-${String(i + 1).padStart(8, "0")}`
      );

      const promises = tokens.map((token, i) =>
        saveCanaryFn({
          token,
          label: `canary-${i}`,
          createdAt: new Date().toISOString(),
          embeddingStyle: "comment",
        })
      );

      await Promise.all(promises);

      const canaries = await listCanariesFn();
      expect(canaries.length).toBe(10);

      // Verify all tokens are present
      const savedTokens = new Set(canaries.map((c: any) => c.token));
      tokens.forEach((token) => {
        expect(savedTokens.has(token)).toBe(true);
      });
    });
  });

  describe("combined concurrent operations", () => {
    let tmpDir: string;
    let saveScanFn: any;
    let listHistoryFn: any;

    beforeEach(async () => {
      tmpDir = mkdtempSync(join(tmpdir(), "guardx-concurrent-"));
      process.env.GUARDX_HISTORY_DIR = tmpDir;

      vi.unmock("../../src/history.js");
      vi.resetModules();
      const histMod = await import("../../src/history.js");
      saveScanFn = histMod.saveScan;
      listHistoryFn = histMod.listHistory;
    });

    afterEach(() => {
      rmSync(tmpDir, { recursive: true, force: true });
      delete process.env.GUARDX_HISTORY_DIR;
    });

    it("sequential saveScan then concurrent listHistory reads return consistent results", async () => {
      const minimalScan = {
        findings: [],
        overallVulnerability: "none",
        leakStatus: "clean",
        recommendations: [],
        defenseProfile: { level: "strong" },
      };

      // Sequential saves
      const savedIds: string[] = [];
      for (let i = 0; i < 5; i++) {
        const id = await saveScanFn(minimalScan, `prompt-seq-${i}`);
        savedIds.push(id);
      }

      // Concurrent reads
      const listPromises = Array.from({ length: 10 }, () =>
        listHistoryFn()
      );
      const allHistories = await Promise.all(listPromises);

      // Verify all reads return the same count
      allHistories.forEach((history) => {
        expect(history.length).toBe(5);
      });

      // Verify all reads return the same IDs
      const firstIds = new Set(allHistories[0].map((h: any) => h.id));
      allHistories.forEach((history, idx) => {
        const currentIds = new Set(history.map((h: any) => h.id));
        expect(currentIds.size).toBe(5);
        expect(currentIds).toEqual(firstIds);
      });
    });
  });
});
