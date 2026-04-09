import { getHistoryScan } from "./history.js";

export interface DiffFinding {
  technique?: string;
  category?: string;
  contentType?: string;
  severity?: string;
  [key: string]: unknown;
}

export interface DiffResult {
  newFindings: DiffFinding[];
  resolvedFindings: DiffFinding[];
  persistingFindings: DiffFinding[];
  regressionDetected: boolean;
  vulnerabilityDelta: string;
  summary: string;
}

export interface DiffScansInput {
  baselineScanId: string;
  currentScanId?: string;
  systemPrompt?: string;
  mode?: "extraction" | "injection" | "dual";
}

function findingKey(f: DiffFinding): string {
  return `${f.technique ?? ""}::${f.category ?? ""}::${f.contentType ?? ""}`;
}

export function diffScanObjects(
  baseline: { findings?: DiffFinding[]; overallVulnerability?: string },
  current: { findings?: DiffFinding[]; overallVulnerability?: string }
): DiffResult {
  const baseFindings = (baseline.findings ?? []) as DiffFinding[];
  const currFindings = (current.findings ?? []) as DiffFinding[];

  const baseKeys = new Map<string, DiffFinding>();
  for (const f of baseFindings) {
    const key = findingKey(f);
    if (!baseKeys.has(key)) baseKeys.set(key, f);
  }

  const currKeys = new Map<string, DiffFinding>();
  for (const f of currFindings) {
    const key = findingKey(f);
    if (!currKeys.has(key)) currKeys.set(key, f);
  }

  const newFindings: DiffFinding[] = [];
  const persistingFindings: DiffFinding[] = [];
  const resolvedFindings: DiffFinding[] = [];

  for (const [key, f] of currKeys) {
    if (baseKeys.has(key)) {
      persistingFindings.push(f);
    } else {
      newFindings.push(f);
    }
  }

  for (const [key, f] of baseKeys) {
    if (!currKeys.has(key)) {
      resolvedFindings.push(f);
    }
  }

  const regressionDetected = newFindings.some(
    (f) => f.severity === "critical" || f.severity === "high"
  );

  const baseVuln = baseline.overallVulnerability ?? "unknown";
  const currVuln = current.overallVulnerability ?? "unknown";
  const vulnerabilityDelta =
    baseVuln === currVuln
      ? `${baseVuln} → ${currVuln} (unchanged)`
      : `${baseVuln} → ${currVuln}`;

  const parts: string[] = [];
  if (newFindings.length > 0) parts.push(`${newFindings.length} new finding(s)`);
  if (resolvedFindings.length > 0) parts.push(`${resolvedFindings.length} resolved`);
  if (persistingFindings.length > 0) parts.push(`${persistingFindings.length} persisting`);
  if (regressionDetected) parts.push("REGRESSION DETECTED");
  const summary =
    parts.length > 0 ? parts.join(", ") + "." : "No changes detected.";

  return {
    newFindings,
    resolvedFindings,
    persistingFindings,
    regressionDetected,
    vulnerabilityDelta,
    summary,
  };
}

export async function diffScans(input: DiffScansInput): Promise<DiffResult> {
  if (!input.baselineScanId || !input.baselineScanId.trim()) {
    throw new Error(
      "Missing required parameter: baselineScanId must be a non-empty string."
    );
  }

  if (input.currentScanId && input.systemPrompt) {
    throw new Error(
      "currentScanId and systemPrompt are mutually exclusive — provide one or the other, not both."
    );
  }

  const baseline = getHistoryScan(input.baselineScanId);
  if (!baseline) {
    throw new Error(`Baseline scan not found: ${input.baselineScanId}`);
  }

  let current: Record<string, unknown>;

  if (input.currentScanId) {
    const c = getHistoryScan(input.currentScanId);
    if (!c) {
      throw new Error(`Current scan not found: ${input.currentScanId}`);
    }
    current = c;
  } else if (input.systemPrompt) {
    const { runSecurityScan } = await import("zeroleaks");
    const apiKey = process.env.OPENROUTER_API_KEY;
    if (!apiKey) {
      throw new Error(
        "OPENROUTER_API_KEY not set — cannot run fresh scan for diff."
      );
    }
    const scanOptions: Parameters<typeof runSecurityScan>[1] = {
      apiKey,
      onProgress: async (_turn: number, _max: number) => {},
    };
    if (input.mode && input.mode !== "dual") {
      scanOptions.scanMode = input.mode;
      scanOptions.enableDualMode = false;
    } else {
      scanOptions.enableDualMode = true;
    }
    const result = await runSecurityScan(input.systemPrompt, scanOptions);
    current = result as Record<string, unknown>;
  } else {
    throw new Error(
      "Provide either currentScanId or systemPrompt to compare against the baseline."
    );
  }

  return diffScanObjects(
    baseline as { findings?: DiffFinding[]; overallVulnerability?: string },
    current as { findings?: DiffFinding[]; overallVulnerability?: string }
  );
}
