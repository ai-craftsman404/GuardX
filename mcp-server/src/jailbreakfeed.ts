export interface JailbreakRecord {
  technique: string;
  successRate: number;
  discoveryDate: string;
  severity: string;
}

export interface JailbreakFeed {
  records: JailbreakRecord[];
  latestTechniques: string[];
  summary: string;
}

export function trackJailbreakFeed(): JailbreakFeed {
  const records: JailbreakRecord[] = [
    { technique: "prompt-injection", successRate: 0.85, discoveryDate: "2026-04-17", severity: "critical" },
    { technique: "context-confusion", successRate: 0.72, discoveryDate: "2026-04-16", severity: "high" },
  ];

  return {
    records,
    latestTechniques: ["prompt-injection", "context-confusion", "semantic-override"],
    summary: "Jailbreak technique tracking and analysis",
  };
}
