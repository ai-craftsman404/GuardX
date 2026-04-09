import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { tmpdir } from "os";
import { join } from "path";
import { existsSync, mkdirSync, rmSync, writeFileSync, readFileSync } from "fs";
import { randomBytes } from "crypto";

// No top-level import of history.ts — it reads GUARDX_HISTORY_DIR at module load time.
// We set the env var before each dynamic import via vi.resetModules().

type HistoryModule = typeof import("../../src/history.js");

const tmpDir = join(tmpdir(), `guardx-hist-${randomBytes(4).toString("hex")}`);

let mod: HistoryModule;

beforeAll(async () => {
  process.env.GUARDX_HISTORY_DIR = tmpDir;
  vi.resetModules();
  mod = await import("../../src/history.js");
});

afterAll(() => {
  delete process.env.GUARDX_HISTORY_DIR;
  if (existsSync(tmpDir)) rmSync(tmpDir, { recursive: true, force: true });
  vi.resetModules();
});

describe("history module — saveScan", () => {
  it("auto-creates HISTORY_DIR if it does not exist", async () => {
    const freshDir = join(tmpdir(), `guardx-autocreate-${randomBytes(4).toString("hex")}`);
    expect(existsSync(freshDir)).toBe(false);

    process.env.GUARDX_HISTORY_DIR = freshDir;
    vi.resetModules();
    const freshMod: HistoryModule = await import("../../src/history.js");
    freshMod.saveScan({ findings: [] }, "autocreate test");

    expect(existsSync(freshDir)).toBe(true);

    rmSync(freshDir, { recursive: true, force: true });
    process.env.GUARDX_HISTORY_DIR = tmpDir;
    vi.resetModules();
    mod = await import("../../src/history.js");
  });

  it("returns a non-empty string ID", () => {
    const id = mod.saveScan({ overallVulnerability: "low", leakStatus: "none", findings: [] }, "Test prompt");
    expect(typeof id).toBe("string");
    expect(id.length).toBeGreaterThan(0);
  });

  it("writes a JSON file to the history directory", () => {
    const id = mod.saveScan({ overallVulnerability: "medium", leakStatus: "hint", findings: [] }, "Another prompt");
    const filePath = join(tmpDir, `${id}.json`);
    expect(existsSync(filePath)).toBe(true);
  });

  it("saved file contains id, promptHash, scannedAt, and result fields", () => {
    const id = mod.saveScan(
      { overallVulnerability: "high", leakStatus: "substantial", findings: [{ id: "f1" }] },
      "You are a helpful assistant."
    );
    const data = JSON.parse(readFileSync(join(tmpDir, `${id}.json`), "utf8"));
    expect(data).toHaveProperty("id", id);
    expect(data).toHaveProperty("promptHash");
    expect(typeof data.promptHash).toBe("string");
    expect(data.promptHash).toHaveLength(8);
    expect(data).toHaveProperty("scannedAt");
    expect(() => new Date(data.scannedAt)).not.toThrow();
    expect(data).toHaveProperty("overallVulnerability", "high");
    expect(data).toHaveProperty("leakStatus", "substantial");
    expect(Array.isArray(data.findings)).toBe(true);
    expect(data.findings).toHaveLength(1);
  });

  it("produces different promptHash for different prompts", () => {
    const id1 = mod.saveScan({ findings: [] }, "Prompt A");
    const id2 = mod.saveScan({ findings: [] }, "Prompt B");
    const d1 = JSON.parse(readFileSync(join(tmpDir, `${id1}.json`), "utf8"));
    const d2 = JSON.parse(readFileSync(join(tmpDir, `${id2}.json`), "utf8"));
    expect(d1.promptHash).not.toBe(d2.promptHash);
  });

  it("produces identical promptHash for the same prompt text", () => {
    const id1 = mod.saveScan({ findings: [] }, "Same prompt");
    const id2 = mod.saveScan({ findings: [] }, "Same prompt");
    const d1 = JSON.parse(readFileSync(join(tmpDir, `${id1}.json`), "utf8"));
    const d2 = JSON.parse(readFileSync(join(tmpDir, `${id2}.json`), "utf8"));
    expect(d1.promptHash).toBe(d2.promptHash);
  });
});

describe("history module — listHistory", () => {
  it("returns an array", () => {
    const entries = mod.listHistory();
    expect(Array.isArray(entries)).toBe(true);
  });

  it("returned entries have expected shape", () => {
    mod.saveScan({ overallVulnerability: "critical", leakStatus: "complete", findings: [{ id: "f1" }, { id: "f2" }] }, "shaped prompt");
    const entries = mod.listHistory();
    expect(entries.length).toBeGreaterThan(0);
    const e = entries[0];
    expect(e).toHaveProperty("id");
    expect(e).toHaveProperty("scannedAt");
    expect(e).toHaveProperty("vulnerability");
    expect(e).toHaveProperty("leakStatus");
    expect(e).toHaveProperty("promptHash");
    expect(e).toHaveProperty("findingsCount");
    expect(typeof e.findingsCount).toBe("number");
  });

  it("returns entries ordered newest first", async () => {
    // Create an isolated temp dir to control exactly which files exist
    const orderedDir = join(tmpdir(), `guardx-order-${randomBytes(4).toString("hex")}`);
    mkdirSync(orderedDir, { recursive: true });

    try {
      process.env.GUARDX_HISTORY_DIR = orderedDir;
      vi.resetModules();
      const orderedMod: HistoryModule = await import("../../src/history.js");

      const id1 = orderedMod.saveScan({ overallVulnerability: "low", leakStatus: "none", findings: [] }, "first");
      await new Promise((r) => setTimeout(r, 5));
      const id2 = orderedMod.saveScan({ overallVulnerability: "high", leakStatus: "substantial", findings: [] }, "second");

      const entries = orderedMod.listHistory();
      expect(entries).toHaveLength(2);
      expect(entries[0].id).toBe(id2); // newest first
      expect(entries[1].id).toBe(id1);
    } finally {
      rmSync(orderedDir, { recursive: true, force: true });
      process.env.GUARDX_HISTORY_DIR = tmpDir;
      vi.resetModules();
      mod = await import("../../src/history.js");
    }
  });

  it("skips corrupted JSON files without throwing", () => {
    const corruptPath = join(tmpDir, `0000000000000-corrupt.json`);
    writeFileSync(corruptPath, "{ not valid json !!!}");
    expect(() => mod.listHistory()).not.toThrow();
    const entries = mod.listHistory();
    expect(entries.every((e) => e !== null)).toBe(true);
  });

  it("returns empty array when history directory contains no JSON files", async () => {
    const emptyDir = join(tmpdir(), `guardx-empty-${randomBytes(4).toString("hex")}`);
    mkdirSync(emptyDir, { recursive: true });
    try {
      process.env.GUARDX_HISTORY_DIR = emptyDir;
      vi.resetModules();
      const emptyMod: HistoryModule = await import("../../src/history.js");
      expect(emptyMod.listHistory()).toEqual([]);
    } finally {
      rmSync(emptyDir, { recursive: true, force: true });
      process.env.GUARDX_HISTORY_DIR = tmpDir;
      vi.resetModules();
      mod = await import("../../src/history.js");
    }
  });
});

describe("history module — getHistoryScan", () => {
  it("returns the full saved record for a valid ID", () => {
    const id = mod.saveScan(
      { overallVulnerability: "critical", leakStatus: "complete", findings: [{ id: "f1", severity: "critical" }] },
      "retrieve me"
    );
    const record = mod.getHistoryScan(id);
    expect(record).not.toBeNull();
    expect(record).toHaveProperty("id", id);
    expect(record).toHaveProperty("overallVulnerability", "critical");
    expect(record).toHaveProperty("promptHash");
  });

  it("returns null for a non-existent ID", () => {
    const result = mod.getHistoryScan("totally-fake-id-99999");
    expect(result).toBeNull();
  });

  it("returns null for an ID with path traversal characters", () => {
    const result = mod.getHistoryScan("../../etc/passwd");
    expect(result).toBeNull();
  });
});
