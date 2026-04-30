import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "fs";
import * as path from "path";
import {
  syncJailbreakFeed,
  listFeedUpdates,
  SyncResult,
  FeedEntry,
} from "../../src/jailbreakfeed.js";

const TEST_DIR = path.join(process.cwd(), ".guardx-test-feed");

beforeEach(() => {
  if (!fs.existsSync(TEST_DIR)) {
    fs.mkdirSync(TEST_DIR, { recursive: true });
  }
});

afterEach(() => {
  if (fs.existsSync(TEST_DIR)) {
    fs.rmSync(TEST_DIR, { recursive: true, force: true });
  }
});

describe("jailbreakfeed", () => {
  it("successful sync returns correct counts for new techniques", async () => {
    const mockResponse = {
      data: [
        {
          technique: "prompt-injection-v1",
          successRate: 0.85,
          discoveryDate: "2026-04-28",
          severity: "critical",
          source: "prompthub",
        },
        {
          technique: "context-confusion-v2",
          successRate: 0.72,
          discoveryDate: "2026-04-29",
          severity: "high",
          source: "prompthub",
        },
        {
          technique: "semantic-override-v1",
          successRate: 0.65,
          discoveryDate: "2026-04-30",
          severity: "medium",
          source: "prompthub",
        },
      ],
    };

    // Mock fetch
    global.fetch = vi.fn(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      } as any)
    );

    const result = await syncJailbreakFeed({ feedDir: TEST_DIR });

    expect(result.newTechniques).toBe(3);
    expect(result.updatedTechniques).toBe(0);
    expect(result.feedPath).toContain(TEST_DIR);
    expect(fs.existsSync(result.feedPath)).toBe(true);
  });

  it("dryRun=true returns counts without writing to disk", async () => {
    const mockResponse = {
      data: [
        {
          technique: "technique-1",
          successRate: 0.8,
          discoveryDate: "2026-04-28",
          severity: "high",
          source: "prompthub",
        },
        {
          technique: "technique-2",
          successRate: 0.7,
          discoveryDate: "2026-04-29",
          severity: "medium",
          source: "prompthub",
        },
      ],
    };

    global.fetch = vi.fn(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      } as any)
    );

    const result = await syncJailbreakFeed({ dryRun: true, feedDir: TEST_DIR });

    expect(result.newTechniques).toBe(2);
    expect(fs.existsSync(result.feedPath)).toBe(false);
  });

  it("returns zero new techniques when feed is already up to date", async () => {
    // Create existing feed file
    const feedPath = path.join(TEST_DIR, "feed.json");
    const existingFeed: FeedEntry[] = [
      {
        technique: "existing-technique",
        successRate: 0.85,
        discoveryDate: "2026-04-28",
        severity: "critical",
        source: "prompthub",
      },
    ];
    fs.writeFileSync(feedPath, JSON.stringify(existingFeed), "utf-8");

    // Mock fetch returns same technique
    const mockResponse = {
      data: [
        {
          technique: "existing-technique",
          successRate: 0.85,
          discoveryDate: "2026-04-28",
          severity: "critical",
          source: "prompthub",
        },
      ],
    };

    global.fetch = vi.fn(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      } as any)
    );

    const result = await syncJailbreakFeed({ feedDir: TEST_DIR });

    expect(result.newTechniques).toBe(0);
  });

  it("falls back to static snapshot on network error", async () => {
    global.fetch = vi.fn(() => Promise.reject(new Error("Network error")));

    const result = await syncJailbreakFeed({ feedDir: TEST_DIR });

    // Should have some default techniques from fallback
    expect(result.newTechniques).toBeGreaterThanOrEqual(0);
    expect(fs.existsSync(result.feedPath)).toBe(true);
  });

  it("deduplicates techniques by name", async () => {
    const mockResponse = {
      data: [
        {
          technique: "prompt-injection",
          successRate: 0.85,
          discoveryDate: "2026-04-28",
          severity: "critical",
          source: "prompthub",
        },
        {
          technique: "prompt-injection",
          successRate: 0.86,
          discoveryDate: "2026-04-28",
          severity: "critical",
          source: "prompthub-v2",
        },
      ],
    };

    global.fetch = vi.fn(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      } as any)
    );

    const result = await syncJailbreakFeed({ feedDir: TEST_DIR });

    // Should deduplicate to 1 technique
    expect(result.newTechniques).toBe(1);

    const feedContent = fs.readFileSync(result.feedPath, "utf-8");
    const feed: FeedEntry[] = JSON.parse(feedContent);
    const promptInjectionCount = feed.filter((e) => e.technique === "prompt-injection").length;
    expect(promptInjectionCount).toBe(1);
  });

  it("listFeedUpdates filters by since date", async () => {
    const feedPath = path.join(TEST_DIR, "feed.json");
    const feed: FeedEntry[] = [
      {
        technique: "old-technique",
        successRate: 0.8,
        discoveryDate: "2026-04-20",
        severity: "high",
        source: "prompthub",
      },
      {
        technique: "new-technique",
        successRate: 0.85,
        discoveryDate: "2026-04-28",
        severity: "critical",
        source: "prompthub",
      },
    ];
    fs.writeFileSync(feedPath, JSON.stringify(feed), "utf-8");

    const updates = listFeedUpdates({
      since: "2026-04-25",
      feedDir: TEST_DIR,
    });

    expect(updates.length).toBe(1);
    expect(updates[0].technique).toBe("new-technique");
  });

  it("listFeedUpdates respects limit parameter", async () => {
    const feedPath = path.join(TEST_DIR, "feed.json");
    const feed: FeedEntry[] = [
      {
        technique: "technique-1",
        successRate: 0.8,
        discoveryDate: "2026-04-28",
        severity: "high",
        source: "prompthub",
      },
      {
        technique: "technique-2",
        successRate: 0.85,
        discoveryDate: "2026-04-29",
        severity: "critical",
        source: "prompthub",
      },
      {
        technique: "technique-3",
        successRate: 0.75,
        discoveryDate: "2026-04-30",
        severity: "medium",
        source: "prompthub",
      },
    ];
    fs.writeFileSync(feedPath, JSON.stringify(feed), "utf-8");

    const updates = listFeedUpdates({
      limit: 2,
      feedDir: TEST_DIR,
    });

    expect(updates.length).toBeLessThanOrEqual(2);
  });

  it("writes feed file and reads it back successfully", async () => {
    const mockResponse = {
      data: [
        {
          technique: "test-technique",
          successRate: 0.9,
          discoveryDate: "2026-04-28",
          severity: "critical",
          source: "prompthub",
        },
      ],
    };

    global.fetch = vi.fn(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      } as any)
    );

    const result = await syncJailbreakFeed({ feedDir: TEST_DIR });

    const feedContent = fs.readFileSync(result.feedPath, "utf-8");
    const feed: FeedEntry[] = JSON.parse(feedContent);

    expect(feed.length).toBe(1);
    expect(feed[0].technique).toBe("test-technique");
    expect(feed[0].successRate).toBe(0.9);
  });

  it("all severity values are valid enum values", async () => {
    const mockResponse = {
      data: [
        {
          technique: "critical-tech",
          successRate: 0.95,
          discoveryDate: "2026-04-28",
          severity: "critical",
          source: "prompthub",
        },
        {
          technique: "high-tech",
          successRate: 0.85,
          discoveryDate: "2026-04-28",
          severity: "high",
          source: "prompthub",
        },
        {
          technique: "medium-tech",
          successRate: 0.75,
          discoveryDate: "2026-04-28",
          severity: "medium",
          source: "prompthub",
        },
        {
          technique: "low-tech",
          successRate: 0.55,
          discoveryDate: "2026-04-28",
          severity: "low",
          source: "prompthub",
        },
      ],
    };

    global.fetch = vi.fn(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      } as any)
    );

    const result = await syncJailbreakFeed({ feedDir: TEST_DIR });
    const feedContent = fs.readFileSync(result.feedPath, "utf-8");
    const feed: FeedEntry[] = JSON.parse(feedContent);

    for (const entry of feed) {
      expect(["critical", "high", "medium", "low"]).toContain(entry.severity);
    }
  });

  it("includes lastSyncAt timestamp in result", async () => {
    const mockResponse = {
      data: [
        {
          technique: "test-tech",
          successRate: 0.8,
          discoveryDate: "2026-04-28",
          severity: "high",
          source: "prompthub",
        },
      ],
    };

    global.fetch = vi.fn(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      } as any)
    );

    const result = await syncJailbreakFeed({ feedDir: TEST_DIR });

    expect(result.lastSyncAt).toBeDefined();
    expect(result.lastSyncAt).toMatch(/\d{4}-\d{2}-\d{2}/);
  });
});
