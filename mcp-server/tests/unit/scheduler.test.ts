import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { tmpdir } from "os";
import { join } from "path";
import { existsSync, readFileSync, rmSync, readdirSync } from "fs";
import { randomBytes } from "crypto";

// Scheduler reads GUARDX_SCHEDULES_DIR at module load time — set before import
type SchedulerModule = typeof import("../../src/scheduler.js");

const tmpDir = join(tmpdir(), `guardx-sched-${randomBytes(4).toString("hex")}`);
let mod: SchedulerModule;

beforeAll(async () => {
  process.env.GUARDX_SCHEDULES_DIR = tmpDir;
  vi.resetModules();
  mod = await import("../../src/scheduler.js");
});

afterAll(() => {
  delete process.env.GUARDX_SCHEDULES_DIR;
  if (existsSync(tmpDir)) rmSync(tmpDir, { recursive: true, force: true });
  vi.resetModules();
});

// ---------------------------------------------------------------------------
// validateCronExpression — pure helper (exported for testing)
// ---------------------------------------------------------------------------

describe("scheduler — validateCronExpression", () => {
  it("accepts standard 5-field daily cron '0 9 * * *'", () => {
    expect(mod.validateCronExpression("0 9 * * *")).toBe(true);
  });

  it("accepts every-minute cron '* * * * *'", () => {
    expect(mod.validateCronExpression("* * * * *")).toBe(true);
  });

  it("accepts weekly cron '0 9 * * 1'", () => {
    expect(mod.validateCronExpression("0 9 * * 1")).toBe(true);
  });

  it("accepts step-value cron '*/15 * * * *'", () => {
    expect(mod.validateCronExpression("*/15 * * * *")).toBe(true);
  });

  it("accepts range cron '0 9-17 * * 1-5'", () => {
    expect(mod.validateCronExpression("0 9-17 * * 1-5")).toBe(true);
  });

  it("rejects fewer than 5 fields", () => {
    expect(mod.validateCronExpression("0 9 * *")).toBe(false);
  });

  it("rejects more than 5 fields", () => {
    expect(mod.validateCronExpression("0 0 9 * * *")).toBe(false);
  });

  it("rejects empty string", () => {
    expect(mod.validateCronExpression("")).toBe(false);
  });

  it("rejects non-cron garbage string", () => {
    expect(mod.validateCronExpression("every day at 9am")).toBe(false);
  });

  it("accepts comma-separated field values '1,15,30 * * * *'", () => {
    expect(mod.validateCronExpression("1,15,30 * * * *")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// computeNextRunAt — pure helper
// ---------------------------------------------------------------------------

describe("scheduler — computeNextRunAt", () => {
  it("returns a valid ISO datetime string", () => {
    const result = mod.computeNextRunAt("0 9 * * *");
    expect(() => new Date(result)).not.toThrow();
    expect(isNaN(new Date(result).getTime())).toBe(false);
  });

  it("returned datetime is in the future", () => {
    const result = mod.computeNextRunAt("* * * * *");
    expect(new Date(result).getTime()).toBeGreaterThan(Date.now());
  });

  it("'0 9 * * *' next run has minute field = 0", () => {
    const result = mod.computeNextRunAt("0 9 * * *");
    const d = new Date(result);
    // Assert minutes only — avoids local-timezone-dependent hour assertions.
    // The implementation uses setHours/getHours consistently in local time, but
    // specific hour assertions are brittle across CI environments with different TZ offsets.
    expect(d.getMinutes()).toBe(0);
  });

  it("'0 0 * * *' next run has minute field = 0", () => {
    const result = mod.computeNextRunAt("0 0 * * *");
    const d = new Date(result);
    expect(d.getMinutes()).toBe(0);
  });

  it("throws for invalid cron expression", () => {
    expect(() => mod.computeNextRunAt("not a cron")).toThrow();
  });
});

// ---------------------------------------------------------------------------
// createScheduledScan
// ---------------------------------------------------------------------------

describe("scheduler — createScheduledScan", () => {
  it("saves a JSON file to the schedules directory", () => {
    const result = mod.createScheduledScan({
      name: "My Daily Scan",
      systemPrompt: "You are a helpful assistant.",
      cronExpression: "0 9 * * *",
    });
    expect(existsSync(join(tmpDir, `${result.scheduleId}.json`))).toBe(true);
  });

  it("returns scheduleId, name, cronExpression, nextRunAt, status", () => {
    const result = mod.createScheduledScan({
      name: "Test Scan",
      systemPrompt: "Prompt.",
      cronExpression: "0 9 * * *",
    });
    expect(typeof result.scheduleId).toBe("string");
    expect(result.name).toBe("Test Scan");
    expect(result.cronExpression).toBe("0 9 * * *");
    expect(typeof result.nextRunAt).toBe("string");
    expect(result.status).toBe("active");
  });

  it("nextRunAt is a valid ISO datetime in the future", () => {
    const result = mod.createScheduledScan({
      name: "Future Scan",
      systemPrompt: "Prompt.",
      cronExpression: "0 9 * * *",
    });
    expect(new Date(result.nextRunAt).getTime()).toBeGreaterThan(Date.now());
  });

  it("throws descriptive error for invalid cron expression", () => {
    expect(() =>
      mod.createScheduledScan({
        name: "Bad Cron",
        systemPrompt: "Prompt.",
        cronExpression: "every day at noon",
      })
    ).toThrow(/cron/i);
  });

  it("throws descriptive error when neither systemPrompt nor promptFile provided", () => {
    expect(() =>
      mod.createScheduledScan({
        name: "No Source",
        cronExpression: "0 9 * * *",
      } as Parameters<typeof mod.createScheduledScan>[0])
    ).toThrow(/systemPrompt.*promptFile|promptFile.*systemPrompt/i);
  });

  it("throws descriptive error when both systemPrompt and promptFile provided", () => {
    expect(() =>
      mod.createScheduledScan({
        name: "Both Sources",
        systemPrompt: "Inline prompt.",
        promptFile: "/path/to/prompt.txt",
        cronExpression: "0 9 * * *",
      })
    ).toThrow(/both|mutually exclusive/i);
  });

  it("uses default mode 'dual' when mode not specified", () => {
    const result = mod.createScheduledScan({
      name: "Default Mode",
      systemPrompt: "Prompt.",
      cronExpression: "0 9 * * *",
    });
    // Load the saved file and verify mode
    const saved = JSON.parse(
      readFileSync(join(tmpDir, `${result.scheduleId}.json`), "utf8")
    );
    expect(saved.mode).toBe("dual");
  });

  it("stores webhookUrl in saved schedule when provided", () => {
    const result = mod.createScheduledScan({
      name: "Webhook Scan",
      systemPrompt: "Prompt.",
      cronExpression: "0 9 * * *",
      webhookUrl: "https://example.com/webhook",
    });
    const saved = JSON.parse(
      readFileSync(join(tmpDir, `${result.scheduleId}.json`), "utf8")
    );
    expect(saved.webhookUrl).toBe("https://example.com/webhook");
  });

  it("default webhookOnSeverity is ['critical', 'high']", () => {
    const result = mod.createScheduledScan({
      name: "Default Severity",
      systemPrompt: "Prompt.",
      cronExpression: "0 9 * * *",
    });
    const saved = JSON.parse(
      readFileSync(join(tmpDir, `${result.scheduleId}.json`), "utf8")
    );
    expect(saved.webhookOnSeverity).toEqual(
      expect.arrayContaining(["critical", "high"])
    );
    expect(saved.webhookOnSeverity).toHaveLength(2);
  });

  it("custom webhookOnSeverity is persisted", () => {
    const result = mod.createScheduledScan({
      name: "Custom Severity",
      systemPrompt: "Prompt.",
      cronExpression: "0 9 * * *",
      webhookOnSeverity: ["critical"],
    });
    const saved = JSON.parse(
      readFileSync(join(tmpDir, `${result.scheduleId}.json`), "utf8")
    );
    expect(saved.webhookOnSeverity).toEqual(["critical"]);
  });

  it("each call generates a unique scheduleId", () => {
    const r1 = mod.createScheduledScan({
      name: "S1",
      systemPrompt: "P.",
      cronExpression: "* * * * *",
    });
    const r2 = mod.createScheduledScan({
      name: "S2",
      systemPrompt: "P.",
      cronExpression: "* * * * *",
    });
    expect(r1.scheduleId).not.toBe(r2.scheduleId);
  });

  it("accepts promptFile as sole prompt source without throwing", () => {
    const result = mod.createScheduledScan({
      name: "File-Only Scan",
      promptFile: "/path/to/prompt.txt",
      cronExpression: "0 9 * * *",
    });
    expect(typeof result.scheduleId).toBe("string");
    expect(result.name).toBe("File-Only Scan");
    expect(existsSync(join(tmpDir, `${result.scheduleId}.json`))).toBe(true);
  });

  it("persists all core fields (scheduleId, name, cronExpression, status, systemPrompt) to JSON file", () => {
    const result = mod.createScheduledScan({
      name: "Persistence Test",
      systemPrompt: "Persist me.",
      cronExpression: "0 10 * * *",
    });
    const saved = JSON.parse(
      readFileSync(join(tmpDir, `${result.scheduleId}.json`), "utf8")
    );
    expect(saved.scheduleId).toBe(result.scheduleId);
    expect(saved.name).toBe("Persistence Test");
    expect(saved.cronExpression).toBe("0 10 * * *");
    expect(saved.status).toBe("active");
    expect(saved.systemPrompt).toBe("Persist me.");
    expect(typeof saved.nextRunAt).toBe("string");
  });
});

// ---------------------------------------------------------------------------
// listScheduledScans
// ---------------------------------------------------------------------------

describe("scheduler — listScheduledScans", () => {
  it("returns empty schedules array when no schedule files exist", () => {
    const emptyDir = join(tmpdir(), `guardx-empty-${randomBytes(4).toString("hex")}`);
    const prevDir = process.env.GUARDX_SCHEDULES_DIR;
    process.env.GUARDX_SCHEDULES_DIR = emptyDir;
    vi.resetModules();
    try {
      // listScheduledScans accepts an override dir — avoids depending on module-level env reload
      const result = mod.listScheduledScans(emptyDir);
      expect(result.schedules).toHaveLength(0);
    } finally {
      if (existsSync(emptyDir)) rmSync(emptyDir, { recursive: true, force: true });
      process.env.GUARDX_SCHEDULES_DIR = prevDir ?? tmpDir;
    }
  });

  it("returns all schedules that were created", () => {
    const before = mod.listScheduledScans().schedules.length;
    mod.createScheduledScan({
      name: "List Test 1",
      systemPrompt: "P.",
      cronExpression: "0 10 * * *",
    });
    mod.createScheduledScan({
      name: "List Test 2",
      systemPrompt: "P.",
      cronExpression: "0 11 * * *",
    });
    const after = mod.listScheduledScans().schedules;
    expect(after.length).toBe(before + 2);
  });

  it("each returned schedule has required fields", () => {
    mod.createScheduledScan({
      name: "Fields Test",
      systemPrompt: "P.",
      cronExpression: "0 12 * * *",
    });
    const result = mod.listScheduledScans();
    for (const s of result.schedules) {
      expect(typeof s.scheduleId).toBe("string");
      expect(typeof s.name).toBe("string");
      expect(typeof s.cronExpression).toBe("string");
      expect(typeof s.nextRunAt).toBe("string");
      expect(["active", "paused", "error"]).toContain(s.status);
    }
  });
});

// ---------------------------------------------------------------------------
// deleteScheduledScan
// ---------------------------------------------------------------------------

describe("scheduler — deleteScheduledScan", () => {
  it("removes the schedule file and returns { deleted: true }", () => {
    const created = mod.createScheduledScan({
      name: "To Delete",
      systemPrompt: "P.",
      cronExpression: "0 8 * * *",
    });
    const filePath = join(tmpDir, `${created.scheduleId}.json`);
    expect(existsSync(filePath)).toBe(true);

    const result = mod.deleteScheduledScan(created.scheduleId);
    expect(result.deleted).toBe(true);
    expect(existsSync(filePath)).toBe(false);
  });

  it("removes only the targeted schedule, not others", () => {
    const keep = mod.createScheduledScan({
      name: "Keep",
      systemPrompt: "P.",
      cronExpression: "0 7 * * *",
    });
    const remove = mod.createScheduledScan({
      name: "Remove",
      systemPrompt: "P.",
      cronExpression: "0 6 * * *",
    });
    mod.deleteScheduledScan(remove.scheduleId);
    expect(existsSync(join(tmpDir, `${keep.scheduleId}.json`))).toBe(true);
    expect(existsSync(join(tmpDir, `${remove.scheduleId}.json`))).toBe(false);
  });

  it("throws descriptive error for unknown scheduleId", () => {
    expect(() =>
      mod.deleteScheduledScan("nonexistent-id-xxxxxx")
    ).toThrow(/not found|unknown|no schedule/i);
  });
});

// ---------------------------------------------------------------------------
// buildWebhookPayload — pure function
// ---------------------------------------------------------------------------

describe("scheduler — buildWebhookPayload", () => {
  it("includes all required fields in payload", () => {
    const payload = mod.buildWebhookPayload({
      scheduleId: "sched-001",
      scheduleName: "Daily Scan",
      regressionCount: 2,
      newFindings: [{ id: "f1", severity: "critical" }],
      scanId: "scan-abc",
      scannedAt: "2026-04-05T09:00:00Z",
      reportUrl: ".guardx/reports/scan-abc.html",
    });
    expect(payload.event).toBe("regression_detected");
    expect(payload.scheduleId).toBe("sched-001");
    expect(payload.scheduleName).toBe("Daily Scan");
    expect(payload.regressionCount).toBe(2);
    expect(Array.isArray(payload.newFindings)).toBe(true);
    expect(payload.scanId).toBe("scan-abc");
    expect(payload.scannedAt).toBe("2026-04-05T09:00:00Z");
    expect(payload.reportUrl).toBe(".guardx/reports/scan-abc.html");
  });

  it("event field is always 'regression_detected'", () => {
    const payload = mod.buildWebhookPayload({
      scheduleId: "x",
      scheduleName: "x",
      regressionCount: 0,
      newFindings: [],
      scanId: "x",
      scannedAt: "2026-01-01T00:00:00Z",
      reportUrl: "x",
    });
    expect(payload.event).toBe("regression_detected");
  });

  it("newFindings is an array (may be empty for 0 regressions)", () => {
    const payload = mod.buildWebhookPayload({
      scheduleId: "x",
      scheduleName: "x",
      regressionCount: 0,
      newFindings: [],
      scanId: "x",
      scannedAt: "2026-01-01T00:00:00Z",
      reportUrl: "x",
    });
    expect(Array.isArray(payload.newFindings)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// webhookOnSeverity filter logic
// ---------------------------------------------------------------------------

describe("scheduler — webhookOnSeverity filter", () => {
  it("shouldTriggerWebhook returns true when finding severity is in the filter list", () => {
    expect(
      mod.shouldTriggerWebhook("critical", ["critical", "high"])
    ).toBe(true);
    expect(mod.shouldTriggerWebhook("high", ["critical", "high"])).toBe(true);
  });

  it("shouldTriggerWebhook returns false when finding severity is not in the filter list", () => {
    expect(
      mod.shouldTriggerWebhook("medium", ["critical", "high"])
    ).toBe(false);
    expect(mod.shouldTriggerWebhook("low", ["critical", "high"])).toBe(false);
  });

  it("shouldTriggerWebhook handles empty filter list (never trigger)", () => {
    expect(mod.shouldTriggerWebhook("critical", [])).toBe(false);
  });

  it("shouldTriggerWebhook handles all severities in filter list", () => {
    const allSevs = ["critical", "high", "medium", "low"];
    for (const s of allSevs) {
      expect(mod.shouldTriggerWebhook(s, allSevs)).toBe(true);
    }
  });
});
