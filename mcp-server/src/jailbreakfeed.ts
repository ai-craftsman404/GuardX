import * as fs from "fs";
import * as path from "path";

export interface FeedEntry {
  technique: string;
  successRate: number;
  discoveryDate: string;
  severity: "critical" | "high" | "medium" | "low";
  source: string;
}

export interface SyncResult {
  newTechniques: number;
  updatedTechniques: number;
  lastSyncAt: string;
  feedPath: string;
}

const DEFAULT_STATIC_FEED: FeedEntry[] = [
  {
    technique: "prompt-injection",
    successRate: 0.85,
    discoveryDate: "2026-04-17",
    severity: "critical",
    source: "static-fallback",
  },
  {
    technique: "context-confusion",
    successRate: 0.72,
    discoveryDate: "2026-04-16",
    severity: "high",
    source: "static-fallback",
  },
  {
    technique: "semantic-override",
    successRate: 0.65,
    discoveryDate: "2026-04-15",
    severity: "medium",
    source: "static-fallback",
  },
  {
    technique: "agent-escalation",
    successRate: 0.58,
    discoveryDate: "2026-04-14",
    severity: "high",
    source: "static-fallback",
  },
];

export async function syncJailbreakFeed(options?: {
  dryRun?: boolean;
  feedDir?: string;
}): Promise<SyncResult> {
  const feedDir = options?.feedDir || path.join(process.cwd(), ".guardx");
  const feedPath = path.join(feedDir, "feed.json");
  const dryRun = options?.dryRun || false;

  // Ensure directory exists
  if (!fs.existsSync(feedDir)) {
    fs.mkdirSync(feedDir, { recursive: true });
  }

  let existingFeed: FeedEntry[] = [];
  if (fs.existsSync(feedPath)) {
    const content = fs.readFileSync(feedPath, "utf-8");
    existingFeed = JSON.parse(content);
  }

  let fetchedFeed: FeedEntry[] = [];

  try {
    // Fetch from PromptHub
    const response = await fetch(
      "https://prompthub.us/api/jailbreaks?limit=50"
    );

    if (response.ok) {
      const data = await response.json();
      if (data.data && Array.isArray(data.data)) {
        fetchedFeed = data.data;
      }
    } else {
      fetchedFeed = DEFAULT_STATIC_FEED;
    }
  } catch {
    // Fallback to static snapshot on network error
    fetchedFeed = DEFAULT_STATIC_FEED;
  }

  // Deduplicate within fetched feed first
  const seenTechniques = new Set<string>();
  const deduplicatedFetched = fetchedFeed.filter((f) => {
    if (seenTechniques.has(f.technique)) {
      return false;
    }
    seenTechniques.add(f.technique);
    return true;
  });

  // Then find new techniques not in existing feed
  const existingTechniques = new Set(existingFeed.map((e) => e.technique));
  const newTechniques = deduplicatedFetched.filter(
    (f) => !existingTechniques.has(f.technique)
  );

  // Merge feeds (deduplicated fetched + existing)
  const mergedFeed = [...deduplicatedFetched, ...existingFeed];

  if (!dryRun) {
    fs.writeFileSync(feedPath, JSON.stringify(mergedFeed, null, 2), "utf-8");
  }

  return {
    newTechniques: newTechniques.length,
    updatedTechniques: 0,
    lastSyncAt: new Date().toISOString().split("T")[0],
    feedPath,
  };
}

export function listFeedUpdates(options?: {
  since?: string;
  limit?: number;
  feedDir?: string;
}): FeedEntry[] {
  const feedDir = options?.feedDir || path.join(process.cwd(), ".guardx");
  const feedPath = path.join(feedDir, "feed.json");

  if (!fs.existsSync(feedPath)) {
    return [];
  }

  const content = fs.readFileSync(feedPath, "utf-8");
  let feed: FeedEntry[] = JSON.parse(content);

  // Filter by since date
  if (options?.since) {
    feed = feed.filter((entry) => entry.discoveryDate >= options.since!);
  }

  // Apply limit
  if (options?.limit) {
    feed = feed.slice(0, options.limit);
  }

  return feed;
}
