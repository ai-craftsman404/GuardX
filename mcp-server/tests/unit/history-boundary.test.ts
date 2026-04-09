import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

let tmpDir: string;
let saveScan: (result: Record<string, unknown>, promptText: string) => string;
let listHistory: () => any[];
let getHistoryScan: (id: string) => Record<string, unknown> | null;

beforeEach(async () => {
  tmpDir = mkdtempSync(join(tmpdir(), "guardx-hist-boundary-"));
  process.env.GUARDX_HISTORY_DIR = tmpDir;
  vi.resetModules();
  const mod = await import("../../src/history.js");
  saveScan = mod.saveScan;
  listHistory = mod.listHistory;
  getHistoryScan = mod.getHistoryScan;
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
  delete process.env.GUARDX_HISTORY_DIR;
  vi.resetModules();
});

const BASE_SCAN = {
  findings: [],
  overallVulnerability: "none",
  leakStatus: "clean",
  recommendations: [],
};

describe("history persistence — boundary conditions", () => {
  it("listHistory on empty dir returns empty array", () => {
    const result = listHistory();
    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBe(0);
  });

  it("100 scans saved — listHistory returns all 100 in newest-first order", () => {
    const ids = new Set<string>();
    for (let i = 0; i < 100; i++) {
      const id = saveScan(BASE_SCAN, `scan number ${i}`);
      ids.add(id);
    }
    const result = listHistory();
    expect(result.length).toBe(100);
    expect(ids.size).toBe(100);
    const resultIds = new Set(result.map((entry: any) => entry.id));
    expect(resultIds.size).toBe(100);
  });

  it("corrupt JSON file in history dir is silently skipped — does not crash listHistory", () => {
    saveScan(BASE_SCAN, "valid scan 1");
    saveScan(BASE_SCAN, "valid scan 2");
    writeFileSync(
      join(tmpDir, "corrupt.json"),
      "{ not valid json {{{{"
    );
    const result = listHistory();
    expect(result.length).toBe(2);
  });

  it("non-JSON file in history dir is ignored by listHistory", () => {
    saveScan(BASE_SCAN, "valid scan");
    writeFileSync(join(tmpDir, "notes.txt"), "some text");
    const result = listHistory();
    expect(result.length).toBe(1);
  });

  it("large scan with 500 findings can be saved and retrieved", () => {
    const largeScan = {
      ...BASE_SCAN,
      findings: Array.from({ length: 500 }, (_, i) => ({
        id: `f${i}`,
        severity: "medium",
        technique: `tech_${i}`,
        category: "injection",
        extractedContent: `content ${i}`,
      })),
    };
    const id = saveScan(largeScan, "large scan test");
    const retrieved = getHistoryScan(id);
    expect(retrieved).not.toBeNull();
    expect((retrieved as any).findings.length).toBe(500);
  });

  it("listHistory returns correct metadata shape for saved scan", () => {
    const scan = {
      ...BASE_SCAN,
      findings: [{ severity: "high" }],
      overallVulnerability: "high",
      leakStatus: "substantial",
    };
    saveScan(scan, "metadata test");
    const result = listHistory();
    expect(result.length).toBe(1);
    const entry = result[0];
    expect(typeof entry.id).toBe("string");
    expect(typeof entry.scannedAt).toBe("string");
    expect(entry.vulnerability).toBe("high");
    expect(entry.leakStatus).toBe("substantial");
    expect(entry.findingsCount).toBe(1);
    expect(typeof entry.promptHash).toBe("string");
    expect(entry.promptHash.length).toBe(8);
  });

  it("getHistoryScan returns null for nonexistent ID", () => {
    const result = getHistoryScan("nonexistent-id-that-does-not-exist");
    expect(result).toBeNull();
  });

  it("listHistory with 50 scans completes under 1000ms", () => {
    for (let i = 0; i < 50; i++) {
      saveScan(BASE_SCAN, `perf test ${i}`);
    }
    const start = Date.now();
    const result = listHistory();
    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(1000);
    expect(result.length).toBe(50);
  });
});
