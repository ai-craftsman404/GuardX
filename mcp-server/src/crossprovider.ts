import { runSecurityScan } from "./scanner.js";
import type { ScanResult, ScanFinding } from "./scanner.js";

export interface ProviderDivergence {
  technique: string;
  providers: Record<string, "critical" | "high" | "medium" | "low">;
  severityGap: number;
}

export interface CrossProviderResult {
  providerResults: Record<string, ScanResult>;
  divergences: ProviderDivergence[];
  consensusFindings: ScanFinding[];
  blindSpots: Record<string, string[]>;
  summary: string;
}

const DEFAULT_PROVIDERS = [
  "anthropic/claude-haiku-4-5-20251001",
  "openai/gpt-4o-mini",
  "google/gemini-flash-1.5",
];

const severityLevel = { critical: 3, high: 2, medium: 1, low: 0 };

export async function runCrossProviderScan(
  systemPrompt: string,
  providers?: string[],
  categories?: string[]
): Promise<CrossProviderResult> {
  const providersToScan = providers && providers.length > 0 ? providers : DEFAULT_PROVIDERS;

  const providerResults: Record<string, ScanResult> = {};
  const allFindings: Record<string, ScanFinding[]> = {};

  // Run scans for each provider
  for (const provider of providersToScan) {
    try {
      const result = await runSecurityScan(systemPrompt, {
        targetModel: provider,
        categories,
      });
      providerResults[provider] = result;
      allFindings[provider] = result.findings;
    } catch (err) {
      // Provider failed, record empty results
      providerResults[provider] = {
        findings: [],
        vulnerability: "secure",
        leakStatus: "none",
        recommendations: [],
        defenseProfiles: [],
        totalTokens: 0,
      };
      allFindings[provider] = [];
    }
  }

  // Find divergences (severity gaps ≥2)
  const divergenceMap = new Map<string, Map<string, "critical" | "high" | "medium" | "low">>();

  for (const [provider, findings] of Object.entries(allFindings)) {
    for (const finding of findings) {
      const key = `${finding.technique}::${finding.category}`;
      if (!divergenceMap.has(key)) {
        divergenceMap.set(key, new Map());
      }
      divergenceMap.get(key)!.set(provider, finding.severity);
    }
  }

  const divergences: ProviderDivergence[] = [];
  for (const [key, providerSeverities] of divergenceMap) {
    if (providerSeverities.size > 1) {
      const severities = Array.from(providerSeverities.values());
      const maxSeverity = Math.max(
        ...severities.map((s) => severityLevel[s])
      );
      const minSeverity = Math.min(
        ...severities.map((s) => severityLevel[s])
      );
      const gap = maxSeverity - minSeverity;

      if (gap >= 2) {
        const [technique, category] = key.split("::");
        divergences.push({
          technique,
          providers: Object.fromEntries(providerSeverities),
          severityGap: gap,
        });
      }
    }
  }

  // Find consensus findings (appear in all providers)
  const consensusFindings: ScanFinding[] = [];
  if (providersToScan.length > 0) {
    const techniqueCountByProvider = new Map<string, number>();

    for (const findings of Object.values(allFindings)) {
      const uniqueTechniques = new Set(findings.map((f) => f.technique));
      for (const tech of uniqueTechniques) {
        techniqueCountByProvider.set(
          tech,
          (techniqueCountByProvider.get(tech) || 0) + 1
        );
      }
    }

    // Consensus = appears in all providers
    for (const [provider, findings] of Object.entries(allFindings)) {
      for (const finding of findings) {
        if (
          techniqueCountByProvider.get(finding.technique) ===
          providersToScan.length
        ) {
          if (!consensusFindings.some((f) => f.technique === finding.technique)) {
            consensusFindings.push(finding);
          }
        }
      }
    }
  }

  // Find blind spots (categories missed by some providers)
  const blindSpots: Record<string, string[]> = {};
  const allCategories = new Set<string>();
  for (const findings of Object.values(allFindings)) {
    for (const finding of findings) {
      allCategories.add(finding.category);
    }
  }

  for (const provider of providersToScan) {
    const providerCategories = new Set(
      allFindings[provider].map((f) => f.category)
    );
    const missed = Array.from(allCategories).filter(
      (cat) => !providerCategories.has(cat)
    );
    if (missed.length > 0) {
      blindSpots[provider] = missed;
    }
  }

  // Generate summary
  const summary =
    `Cross-provider scan: ${providersToScan.length} providers analyzed. ` +
    `${divergences.length} divergences found, ` +
    `${consensusFindings.length} consensus findings. ` +
    `Risk: ${divergences.length > 0 ? "HIGH" : "LOW"}`;

  return {
    providerResults,
    divergences,
    consensusFindings,
    blindSpots,
    summary,
  };
}
