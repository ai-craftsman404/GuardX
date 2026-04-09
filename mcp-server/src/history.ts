import { writeFileSync, readFileSync, readdirSync, mkdirSync, existsSync } from "fs";
import { join } from "path";
import { createHash } from "crypto";

const HISTORY_DIR =
  process.env.GUARDX_HISTORY_DIR ??
  join(process.cwd(), ".guardx", "history");

export interface ScanHistoryMeta {
  id: string;
  scannedAt: string;
  vulnerability: string;
  leakStatus: string;
  promptHash: string;
  findingsCount: number;
}

function ensureDir(dir: string) {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

export function saveScan(
  result: Record<string, unknown>,
  promptText: string
): string {
  ensureDir(HISTORY_DIR);
  const id = `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
  const promptHash = createHash("sha256")
    .update(promptText)
    .digest("hex")
    .slice(0, 8);
  const record = {
    id,
    promptHash,
    scannedAt: new Date().toISOString(),
    ...result,
  };
  writeFileSync(
    join(HISTORY_DIR, `${id}.json`),
    JSON.stringify(record, null, 2)
  );
  return id;
}

export function listHistory(): ScanHistoryMeta[] {
  ensureDir(HISTORY_DIR);
  const files = readdirSync(HISTORY_DIR)
    .filter((f) => f.endsWith(".json"))
    .sort()
    .reverse();

  return files
    .map((f) => {
      try {
        const data = JSON.parse(
          readFileSync(join(HISTORY_DIR, f), "utf8")
        ) as Record<string, unknown>;
        const findings = Array.isArray(data.findings) ? data.findings : [];
        return {
          id: data.id as string,
          scannedAt: (data.scannedAt as string) ?? "",
          vulnerability: (data.overallVulnerability as string) ?? "unknown",
          leakStatus: (data.leakStatus as string) ?? "unknown",
          promptHash: (data.promptHash as string) ?? "unknown",
          findingsCount: findings.length,
        };
      } catch {
        return null;
      }
    })
    .filter(Boolean) as ScanHistoryMeta[];
}

export function getHistoryScan(id: string): Record<string, unknown> | null {
  const filePath = join(HISTORY_DIR, `${id}.json`);
  if (!existsSync(filePath)) return null;
  try {
    return JSON.parse(readFileSync(filePath, "utf8"));
  } catch {
    return null;
  }
}
