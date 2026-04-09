import { describe, it, expect, vi, beforeAll, afterAll, beforeEach, afterEach } from "vitest";
import { tmpdir } from "os";
import { join } from "path";
import { existsSync, readFileSync, writeFileSync, mkdirSync, rmSync } from "fs";
import { randomBytes } from "crypto";

// ── Mocks ────────────────────────────────────────────────────────────────────

const mockRunSecurityScan = vi.fn();
vi.mock("zeroleaks", () => ({
  runSecurityScan: mockRunSecurityScan,
}));

const mockSaveScan = vi.fn().mockReturnValue("mock-scan-id-001");
vi.mock("../../src/history.js", () => ({
  saveScan: mockSaveScan,
}));

// ── Module import ─────────────────────────────────────────────────────────────

type RunnerModule = typeof import("../../src/scheduler-runner.js");
let mod: RunnerModule;

const rootTmp = join(tmpdir(), `guardx-runner-${randomBytes(4).toString("hex")}`);

beforeAll(async () => {
  vi.resetModules();
  mod = await import("../../src/scheduler-runner.js");
});

afterAll(() => {
  if (existsSync(rootTmp)) rmSync(rootTmp, { recursive: true, force: true });
  vi.resetModules();
});

// ── Per-test helpers ──────────────────────────────────────────────────────────

const MOCK_SCAN_CLEAN = {
  findings: [],
  overallVulnerability: "secure",
  leakStatus: "none",
  recommendations: [],
};

const MOCK_SCAN_REGRESSION = {
  findings: [
    { id: "f1", severity: "critical", technique: "direct_extraction", extractedContent: "secret" },
  ],
  overallVulnerability: "critical",
  leakStatus: "leaked",
  recommendations: [],
};

const MOCK_SCAN_LOW_FINDING = {
  findings: [{ id: "f2", severity: "low", technique: "social_eng", extractedContent: "minor" }],
  overallVulnerability: "low_risk",
  leakStatus: "partial",
  recommendations: [],
};

function pastDate(): string {
  return new Date(Date.now() - 120_000).toISOString();
}

function futureDate(): string {
  return new Date(Date.now() + 3_600_000).toISOString();
}

function makeSchedule(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    scheduleId: randomBytes(4).toString("hex"),
    name: "Test Schedule",
    cronExpression: "* * * * *",
    nextRunAt: pastDate(),
    status: "active",
    mode: "dual",
    webhookOnSeverity: ["critical", "high"],
    systemPrompt: "You are a helpful assistant.",
    ...overrides,
  };
}

function writeSchedule(dir: string, sched: Record<string, unknown>): string {
  mkdirSync(dir, { recursive: true });
  const filePath = join(dir, `${sched.scheduleId}.json`);
  writeFileSync(filePath, JSON.stringify(sched, null, 2));
  return filePath;
}

function readSchedule(dir: string, scheduleId: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(dir, `${scheduleId}.json`), "utf8"));
}

function makeTestDir(): string {
  const dir = join(rootTmp, randomBytes(4).toString("hex"));
  mkdirSync(dir, { recursive: true });
  return dir;
}

let originalFetch: typeof global.fetch;

beforeEach(() => {
  mockRunSecurityScan.mockReset().mockResolvedValue(MOCK_SCAN_CLEAN);
  mockSaveScan.mockReset().mockReturnValue("mock-scan-id-001");
  originalFetch = global.fetch;
  global.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200 } as Response);
});

afterEach(() => {
  global.fetch = originalFetch;
});

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("scheduler-runner — due schedule triggers scan", () => {
  it("calls runSecurityScan once for a schedule whose nextRunAt is in the past", async () => {
    const dir = makeTestDir();
    const sched = makeSchedule();
    writeSchedule(dir, sched);

    await mod.runScheduler(dir);

    expect(mockRunSecurityScan).toHaveBeenCalledTimes(1);
  });

  it("passes the schedule's systemPrompt as the first argument to runSecurityScan", async () => {
    const dir = makeTestDir();
    const sched = makeSchedule({ systemPrompt: "My custom system prompt." });
    writeSchedule(dir, sched);

    await mod.runScheduler(dir);

    expect(mockRunSecurityScan).toHaveBeenCalledWith(
      "My custom system prompt.",
      expect.any(Object)
    );
  });

  it("updates nextRunAt to a future time after a successful scan", async () => {
    const dir = makeTestDir();
    const sched = makeSchedule();
    writeSchedule(dir, sched);
    const before = Date.now();

    await mod.runScheduler(dir);

    const updated = readSchedule(dir, sched.scheduleId as string);
    expect(new Date(updated.nextRunAt as string).getTime()).toBeGreaterThan(before);
  });

  it("sets lastRunAt to a recent ISO timestamp after a successful scan", async () => {
    const dir = makeTestDir();
    const sched = makeSchedule();
    writeSchedule(dir, sched);
    const before = Date.now();

    await mod.runScheduler(dir);

    const updated = readSchedule(dir, sched.scheduleId as string);
    const lastRunMs = new Date(updated.lastRunAt as string).getTime();
    expect(lastRunMs).toBeGreaterThanOrEqual(before);
  });
});

describe("scheduler-runner — schedule not yet due is skipped", () => {
  it("does not call runSecurityScan when nextRunAt is in the future", async () => {
    const dir = makeTestDir();
    const sched = makeSchedule({ nextRunAt: futureDate() });
    writeSchedule(dir, sched);

    await mod.runScheduler(dir);

    expect(mockRunSecurityScan).not.toHaveBeenCalled();
  });

  it("leaves the schedule JSON unmodified when skipped", async () => {
    const dir = makeTestDir();
    const sched = makeSchedule({ nextRunAt: futureDate() });
    writeSchedule(dir, sched);
    const original = readSchedule(dir, sched.scheduleId as string);

    await mod.runScheduler(dir);

    const after = readSchedule(dir, sched.scheduleId as string);
    expect(after).toEqual(original);
  });
});

describe("scheduler-runner — paused and error schedules are skipped", () => {
  it("does not scan a paused schedule even when overdue", async () => {
    const dir = makeTestDir();
    const sched = makeSchedule({ status: "paused" });
    writeSchedule(dir, sched);

    await mod.runScheduler(dir);

    expect(mockRunSecurityScan).not.toHaveBeenCalled();
  });

  it("does not scan a schedule with status 'error' even when overdue", async () => {
    const dir = makeTestDir();
    const sched = makeSchedule({ status: "error" });
    writeSchedule(dir, sched);

    await mod.runScheduler(dir);

    expect(mockRunSecurityScan).not.toHaveBeenCalled();
  });
});

describe("scheduler-runner — lastResult values", () => {
  it("sets lastResult to 'clean' when scan returns no findings", async () => {
    mockRunSecurityScan.mockResolvedValue(MOCK_SCAN_CLEAN);
    const dir = makeTestDir();
    const sched = makeSchedule();
    writeSchedule(dir, sched);

    await mod.runScheduler(dir);

    const updated = readSchedule(dir, sched.scheduleId as string);
    expect(updated.lastResult).toBe("clean");
  });

  it("sets lastResult to 'regression' when scan returns findings", async () => {
    mockRunSecurityScan.mockResolvedValue(MOCK_SCAN_REGRESSION);
    const dir = makeTestDir();
    const sched = makeSchedule();
    writeSchedule(dir, sched);

    await mod.runScheduler(dir);

    const updated = readSchedule(dir, sched.scheduleId as string);
    expect(updated.lastResult).toBe("regression");
  });

  it("sets lastResult to 'error' when runSecurityScan throws", async () => {
    mockRunSecurityScan.mockRejectedValue(new Error("API timeout"));
    const dir = makeTestDir();
    const sched = makeSchedule();
    writeSchedule(dir, sched);

    await mod.runScheduler(dir);

    const updated = readSchedule(dir, sched.scheduleId as string);
    expect(updated.lastResult).toBe("error");
  });

  it("still updates nextRunAt when scan throws", async () => {
    mockRunSecurityScan.mockRejectedValue(new Error("API timeout"));
    const dir = makeTestDir();
    const sched = makeSchedule();
    writeSchedule(dir, sched);
    const before = Date.now();

    await mod.runScheduler(dir);

    const updated = readSchedule(dir, sched.scheduleId as string);
    expect(new Date(updated.nextRunAt as string).getTime()).toBeGreaterThan(before);
  });
});

describe("scheduler-runner — webhook behaviour", () => {
  it("calls fetch with the webhookUrl when a critical finding matches webhookOnSeverity", async () => {
    mockRunSecurityScan.mockResolvedValue(MOCK_SCAN_REGRESSION);
    const dir = makeTestDir();
    const sched = makeSchedule({
      webhookUrl: "https://hooks.example.com/notify",
      webhookOnSeverity: ["critical", "high"],
    });
    writeSchedule(dir, sched);

    await mod.runScheduler(dir);

    expect(global.fetch).toHaveBeenCalledTimes(1);
    const [url, init] = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(url).toBe("https://hooks.example.com/notify");
    expect(init.method).toBe("POST");
  });

  it("does not call fetch when finding severity is below webhookOnSeverity threshold", async () => {
    mockRunSecurityScan.mockResolvedValue(MOCK_SCAN_LOW_FINDING);
    const dir = makeTestDir();
    const sched = makeSchedule({
      webhookUrl: "https://hooks.example.com/notify",
      webhookOnSeverity: ["critical", "high"],
    });
    writeSchedule(dir, sched);

    await mod.runScheduler(dir);

    expect(global.fetch).not.toHaveBeenCalled();
  });

  it("does not call fetch when there are no findings", async () => {
    mockRunSecurityScan.mockResolvedValue(MOCK_SCAN_CLEAN);
    const dir = makeTestDir();
    const sched = makeSchedule({
      webhookUrl: "https://hooks.example.com/notify",
      webhookOnSeverity: ["critical", "high"],
    });
    writeSchedule(dir, sched);

    await mod.runScheduler(dir);

    expect(global.fetch).not.toHaveBeenCalled();
  });

  it("does not call fetch when schedule has no webhookUrl", async () => {
    mockRunSecurityScan.mockResolvedValue(MOCK_SCAN_REGRESSION);
    const dir = makeTestDir();
    const sched = makeSchedule({ webhookUrl: undefined, webhookOnSeverity: ["critical", "high"] });
    writeSchedule(dir, sched);

    await mod.runScheduler(dir);

    expect(global.fetch).not.toHaveBeenCalled();
  });

  it("webhook POST body contains expected regression_detected payload fields", async () => {
    mockRunSecurityScan.mockResolvedValue(MOCK_SCAN_REGRESSION);
    const dir = makeTestDir();
    const sched = makeSchedule({
      webhookUrl: "https://hooks.example.com/notify",
      webhookOnSeverity: ["critical", "high"],
    });
    writeSchedule(dir, sched);

    await mod.runScheduler(dir);

    const [, init] = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    const body = JSON.parse(init.body as string);
    expect(body.event).toBe("regression_detected");
    expect(body.scheduleId).toBe(sched.scheduleId);
    expect(typeof body.regressionCount).toBe("number");
    expect(body.regressionCount).toBeGreaterThan(0);
    expect(Array.isArray(body.newFindings)).toBe(true);
    expect(body.newFindings.length).toBeGreaterThan(0);
  });

  it("continues processing remaining schedules when webhook fetch throws", async () => {
    mockRunSecurityScan.mockResolvedValue(MOCK_SCAN_REGRESSION);
    (global.fetch as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error("Network error")
    );
    const dir = makeTestDir();
    const sched1 = makeSchedule({ webhookUrl: "https://hooks.example.com/notify", webhookOnSeverity: ["critical"] });
    const sched2 = makeSchedule();
    writeSchedule(dir, sched1);
    writeSchedule(dir, sched2);

    await expect(mod.runScheduler(dir)).resolves.not.toThrow();
    // Both schedules should have been processed (lastRunAt set)
    const s1 = readSchedule(dir, sched1.scheduleId as string);
    const s2 = readSchedule(dir, sched2.scheduleId as string);
    expect(s1.lastRunAt).toBeDefined();
    expect(s2.lastRunAt).toBeDefined();
  });
});

describe("scheduler-runner — promptFile support", () => {
  it("reads systemPrompt from promptFile when promptFile is set", async () => {
    const dir = makeTestDir();
    const promptPath = join(dir, "my-prompt.txt");
    writeFileSync(promptPath, "You are a pirate assistant.");

    const sched = makeSchedule({ promptFile: promptPath, systemPrompt: undefined });
    writeSchedule(dir, sched);

    await mod.runScheduler(dir);

    expect(mockRunSecurityScan).toHaveBeenCalledWith(
      "You are a pirate assistant.",
      expect.any(Object)
    );
  });

  it("sets lastResult 'error' and advances nextRunAt when promptFile cannot be read", async () => {
    const dir = makeTestDir();
    const sched = makeSchedule({
      promptFile: "/nonexistent/path/prompt.txt",
      systemPrompt: undefined,
    });
    writeSchedule(dir, sched);
    const before = Date.now();

    await mod.runScheduler(dir);

    expect(mockRunSecurityScan).not.toHaveBeenCalled();
    const updated = readSchedule(dir, sched.scheduleId as string);
    expect(updated.lastResult).toBe("error");
    expect(new Date(updated.nextRunAt as string).getTime()).toBeGreaterThan(before);
  });
});

describe("scheduler-runner — empty or missing directory", () => {
  it("returns without error when schedulesDir does not exist", async () => {
    await expect(
      mod.runScheduler(join(rootTmp, "nonexistent-dir"))
    ).resolves.not.toThrow();
  });

  it("does not call runSecurityScan when directory is empty", async () => {
    const dir = makeTestDir(); // empty dir

    await mod.runScheduler(dir);

    expect(mockRunSecurityScan).not.toHaveBeenCalled();
  });
});

describe("scheduler-runner — multiple schedules", () => {
  it("runs all overdue schedules in a directory", async () => {
    const dir = makeTestDir();
    writeSchedule(dir, makeSchedule());
    writeSchedule(dir, makeSchedule());
    writeSchedule(dir, makeSchedule());

    await mod.runScheduler(dir);

    expect(mockRunSecurityScan).toHaveBeenCalledTimes(3);
  });

  it("skips future schedules while running overdue ones", async () => {
    const dir = makeTestDir();
    writeSchedule(dir, makeSchedule());
    writeSchedule(dir, makeSchedule({ nextRunAt: futureDate() }));
    writeSchedule(dir, makeSchedule());

    await mod.runScheduler(dir);

    expect(mockRunSecurityScan).toHaveBeenCalledTimes(2);
  });
});

describe("scheduler-runner — scan mode options", () => {
  it("passes enableDualMode: true for mode 'dual'", async () => {
    const dir = makeTestDir();
    writeSchedule(dir, makeSchedule({ mode: "dual" }));

    await mod.runScheduler(dir);

    const [, opts] = mockRunSecurityScan.mock.calls[0] as [string, Record<string, unknown>];
    expect(opts.enableDualMode).toBe(true);
  });

  it("passes scanMode: 'extraction' and enableDualMode: false for mode 'extraction'", async () => {
    const dir = makeTestDir();
    writeSchedule(dir, makeSchedule({ mode: "extraction" }));

    await mod.runScheduler(dir);

    const [, opts] = mockRunSecurityScan.mock.calls[0] as [string, Record<string, unknown>];
    expect(opts.scanMode).toBe("extraction");
    expect(opts.enableDualMode).toBe(false);
  });

  it("passes scanMode: 'injection' and enableDualMode: false for mode 'injection'", async () => {
    const dir = makeTestDir();
    writeSchedule(dir, makeSchedule({ mode: "injection" }));

    await mod.runScheduler(dir);

    const [, opts] = mockRunSecurityScan.mock.calls[0] as [string, Record<string, unknown>];
    expect(opts.scanMode).toBe("injection");
    expect(opts.enableDualMode).toBe(false);
  });

  it("passes attackerModel, targetModel, evaluatorModel from schedule to scan options", async () => {
    const dir = makeTestDir();
    writeSchedule(dir, makeSchedule({
      attackerModel: "openai/gpt-4o",
      targetModel: "anthropic/claude-3-haiku",
      evaluatorModel: "openai/gpt-4o-mini",
    }));

    await mod.runScheduler(dir);

    const [, opts] = mockRunSecurityScan.mock.calls[0] as [string, Record<string, unknown>];
    expect(opts.attackerModel).toBe("openai/gpt-4o");
    expect(opts.targetModel).toBe("anthropic/claude-3-haiku");
    expect(opts.evaluatorModel).toBe("openai/gpt-4o-mini");
  });
});
