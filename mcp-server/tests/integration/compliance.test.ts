import { describe, it, expect, beforeAll } from "vitest";
import { runSecurityScan } from "zeroleaks";
import { enrichFindings } from "../../src/compliance.js";
import { EVALUATION_PROMPT_REFERENCE } from "../fixtures/autogpt-prompts.js";

const CHEAP_MODEL = "openai/gpt-4o-mini";
const RUN_INTEGRATION = process.env.RUN_INTEGRATION === "true";
const describeIntegration = RUN_INTEGRATION ? describe : describe.skip;

// Known-explicit categories in ATLAS_MAP — any finding with these categories
// must NOT be falling back to the generic AML.T0051-only mapping.
const ATLAS_EXPLICIT_CATEGORIES = new Set([
  "direct", "encoding", "persona", "tool_exploit",
  "injection", "crescendo", "many_shot",
]);

describeIntegration(
  "compliance mapping — integration (requires OPENROUTER_API_KEY + RUN_INTEGRATION=true)",
  () => {
    beforeAll(() => {
      if (!process.env.OPENROUTER_API_KEY) {
        throw new Error("OPENROUTER_API_KEY must be set to run integration tests.");
      }
    });

    it(
      "every finding from a real scan has non-empty MITRE ATLAS and EU AI Act tags",
      async () => {
        const scanResult = await runSecurityScan(EVALUATION_PROMPT_REFERENCE, {
          apiKey: process.env.OPENROUTER_API_KEY!,
          attackerModel: CHEAP_MODEL,
          evaluatorModel: CHEAP_MODEL,
          maxTurns: 5,
          maxDurationMs: 90_000,
          enableDualMode: true,
        });

        expect(scanResult).toBeDefined();
        expect(Array.isArray(scanResult.findings)).toBe(true);

        const enriched = enrichFindings(scanResult as Record<string, unknown>);

        // complianceSummary must be present and populated
        expect(enriched.complianceSummary).toBeDefined();
        expect(Array.isArray(enriched.complianceSummary.atlasTactics)).toBe(true);
        expect(Array.isArray(enriched.complianceSummary.euAiActArticles)).toBe(true);

        if (enriched.findings.length === 0) {
          // No findings on this run — structural checks still pass
          return;
        }

        expect(enriched.complianceSummary.atlasTactics.length).toBeGreaterThan(0);
        expect(enriched.complianceSummary.euAiActArticles.length).toBeGreaterThan(0);

        const fallbackCategories: string[] = [];

        for (const finding of enriched.findings) {
          const category = typeof finding.category === "string" ? finding.category : "";

          // Every finding must have non-empty tags
          expect(finding.atlasTags).toBeDefined();
          expect(Array.isArray(finding.atlasTags)).toBe(true);
          expect((finding.atlasTags as string[]).length).toBeGreaterThan(0);

          expect(finding.euAiActTags).toBeDefined();
          expect(Array.isArray(finding.euAiActTags)).toBe(true);
          expect((finding.euAiActTags as string[]).length).toBeGreaterThan(0);

          // All ATLAS tags must be valid AML format
          for (const tag of finding.atlasTags as string[]) {
            expect(tag).toMatch(/^AML\.T\d{4}$/);
          }

          // All EU AI Act tags must be valid Article format
          for (const tag of finding.euAiActTags as string[]) {
            expect(tag).toMatch(/^Article \d+$/);
          }

          // Track categories that only got the fallback single-tag mapping
          // (explicit categories should have >=2 ATLAS tags)
          if (
            ATLAS_EXPLICIT_CATEGORIES.has(category) &&
            (finding.atlasTags as string[]).length === 1
          ) {
            fallbackCategories.push(category);
          }
        }

        // Warn (but don't fail) for known categories using fallback — signals
        // that compliance.ts ATLAS_MAP needs updating for new zeroleaks techniques.
        if (fallbackCategories.length > 0) {
          console.warn(
            `[compliance] These known categories only produced a single ATLAS tag ` +
            `(may need ATLAS_MAP update): ${[...new Set(fallbackCategories)].join(", ")}`
          );
        }
      },
      300_000
    );

    it(
      "enrichFindings is idempotent — running twice on same result produces same tags",
      async () => {
        const scanResult = await runSecurityScan(EVALUATION_PROMPT_REFERENCE, {
          apiKey: process.env.OPENROUTER_API_KEY!,
          attackerModel: CHEAP_MODEL,
          evaluatorModel: CHEAP_MODEL,
          maxTurns: 3,
          maxDurationMs: 60_000,
          enableDualMode: true,
        });

        const first = enrichFindings(scanResult as Record<string, unknown>);
        const second = enrichFindings(first as unknown as Record<string, unknown>);

        // Tags must be identical on second pass (no double-enrichment)
        expect(second.complianceSummary.atlasTactics).toEqual(
          first.complianceSummary.atlasTactics
        );
        expect(second.complianceSummary.euAiActArticles).toEqual(
          first.complianceSummary.euAiActArticles
        );

        for (let i = 0; i < first.findings.length; i++) {
          expect(second.findings[i].atlasTags).toEqual(first.findings[i].atlasTags);
          expect(second.findings[i].euAiActTags).toEqual(first.findings[i].euAiActTags);
        }
      },
      300_000
    );
  }
);
