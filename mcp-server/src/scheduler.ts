import { writeFileSync, readFileSync, unlinkSync, existsSync, mkdirSync, readdirSync } from "fs";
import { join } from "path";
import { randomBytes } from "crypto";

const SCHEDULES_DIR =
  process.env.GUARDX_SCHEDULES_DIR ??
  join(process.cwd(), ".guardx", "schedules");

function ensureDir(dir: string) {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

function schedulesDir(): string {
  return process.env.GUARDX_SCHEDULES_DIR ?? SCHEDULES_DIR;
}

// ─── Types ────────────────────────────────────────────────────────────────────

export interface CreateScheduledScanArgs {
  name: string;
  systemPrompt?: string;
  promptFile?: string;
  cronExpression: string;
  mode?: "extraction" | "injection" | "dual";
  webhookUrl?: string;
  webhookOnSeverity?: ("critical" | "high" | "medium" | "low")[];
  attackerModel?: string;
  targetModel?: string;
  evaluatorModel?: string;
}

export interface ScheduledScan {
  scheduleId: string;
  name: string;
  cronExpression: string;
  lastRunAt?: string;
  nextRunAt: string;
  lastResult?: "clean" | "regression" | "error";
  status: "active" | "paused" | "error";
  mode: string;
  webhookUrl?: string;
  webhookOnSeverity: string[];
  systemPrompt?: string;
  promptFile?: string;
  attackerModel?: string;
  targetModel?: string;
  evaluatorModel?: string;
}

export interface CreateScheduledScanResult {
  scheduleId: string;
  name: string;
  cronExpression: string;
  nextRunAt: string;
  status: "active";
}

export interface ListScheduledScansResult {
  schedules: ScheduledScan[];
}

export interface DeleteScheduledScanResult {
  deleted: boolean;
}

export interface WebhookPayload {
  event: "regression_detected";
  scheduleId: string;
  scheduleName: string;
  regressionCount: number;
  newFindings: unknown[];
  scanId: string;
  scannedAt: string;
  reportUrl: string;
}

export interface BuildWebhookPayloadArgs {
  scheduleId: string;
  scheduleName: string;
  regressionCount: number;
  newFindings: unknown[];
  scanId: string;
  scannedAt: string;
  reportUrl: string;
}

// ─── Pure helpers ─────────────────────────────────────────────────────────────

/**
 * Validates a 5-field cron expression.
 * Returns true if valid, false otherwise.
 */
export function validateCronExpression(expr: string): boolean {
  if (!expr || !expr.trim()) return false;
  const fields = expr.trim().split(/\s+/);
  if (fields.length !== 5) return false;
  // Each field: number, *, */N, N-M, or comma-separated combination
  const fieldPattern = /^(\*|(\d+(-\d+)?)(,\d+(-\d+)?)*)$|^\*\/\d+$/;
  return fields.every((f) => fieldPattern.test(f));
}

/**
 * Computes the next run datetime for a 5-field cron expression.
 * Returns an ISO string.
 */
export function computeNextRunAt(cronExpression: string): string {
  if (!validateCronExpression(cronExpression)) {
    throw new Error(`Invalid cron expression: "${cronExpression}"`);
  }

  const [minuteField, hourField] = cronExpression.split(/\s+/);
  const now = new Date();
  const next = new Date(now);
  next.setSeconds(0);
  next.setMilliseconds(0);
  // Advance by 1 minute to ensure it's in the future
  next.setMinutes(next.getMinutes() + 1);

  // Parse fixed hour/minute if specified
  const isFixedHour = hourField !== "*" && !hourField.startsWith("*/");
  const isFixedMinute = minuteField !== "*" && !minuteField.startsWith("*/");

  if (isFixedHour && isFixedMinute) {
    const targetHour = parseInt(hourField, 10);
    const targetMinute = parseInt(minuteField, 10);
    next.setHours(targetHour, targetMinute, 0, 0);
    // If time already passed today, advance to tomorrow
    if (next.getTime() <= now.getTime()) {
      next.setDate(next.getDate() + 1);
    }
  } else if (isFixedHour) {
    const targetHour = parseInt(hourField, 10);
    next.setHours(targetHour, 0, 0, 0);
    if (next.getTime() <= now.getTime()) {
      next.setDate(next.getDate() + 1);
    }
  } else if (isFixedMinute) {
    const targetMinute = parseInt(minuteField, 10);
    next.setMinutes(targetMinute, 0, 0);
    if (next.getTime() <= now.getTime()) {
      next.setHours(next.getHours() + 1);
    }
  }
  // For wildcard expressions (e.g. "* * * * *"), next is already 1 minute ahead

  return next.toISOString();
}

export function buildWebhookPayload(args: BuildWebhookPayloadArgs): WebhookPayload {
  return {
    event: "regression_detected",
    scheduleId: args.scheduleId,
    scheduleName: args.scheduleName,
    regressionCount: args.regressionCount,
    newFindings: args.newFindings,
    scanId: args.scanId,
    scannedAt: args.scannedAt,
    reportUrl: args.reportUrl,
  };
}

export function shouldTriggerWebhook(
  severity: string,
  webhookOnSeverity: string[]
): boolean {
  return webhookOnSeverity.includes(severity);
}

// ─── CRUD operations ──────────────────────────────────────────────────────────

export function createScheduledScan(
  args: CreateScheduledScanArgs
): CreateScheduledScanResult {
  if (args.systemPrompt !== undefined && args.promptFile !== undefined) {
    throw new Error(
      "Provide either systemPrompt or promptFile — they are mutually exclusive."
    );
  }
  if (args.systemPrompt === undefined && args.promptFile === undefined) {
    throw new Error(
      "Missing required parameter: provide either systemPrompt (inline text) or promptFile (path to prompt file)."
    );
  }
  if (!validateCronExpression(args.cronExpression)) {
    throw new Error(
      `Invalid cron expression: "${args.cronExpression}". Expected 5 fields e.g. "0 9 * * *".`
    );
  }

  const scheduleId = randomBytes(8).toString("hex");
  const nextRunAt = computeNextRunAt(args.cronExpression);

  const schedule: ScheduledScan = {
    scheduleId,
    name: args.name,
    cronExpression: args.cronExpression,
    nextRunAt,
    status: "active",
    mode: args.mode ?? "dual",
    webhookUrl: args.webhookUrl,
    webhookOnSeverity: args.webhookOnSeverity ?? ["critical", "high"],
    systemPrompt: args.systemPrompt,
    promptFile: args.promptFile,
    attackerModel: args.attackerModel,
    targetModel: args.targetModel,
    evaluatorModel: args.evaluatorModel,
  };

  const dir = schedulesDir();
  ensureDir(dir);
  writeFileSync(join(dir, `${scheduleId}.json`), JSON.stringify(schedule, null, 2));

  return { scheduleId, name: args.name, cronExpression: args.cronExpression, nextRunAt, status: "active" };
}

export function listScheduledScans(overrideDir?: string): ListScheduledScansResult {
  const dir = overrideDir ?? schedulesDir();
  if (!existsSync(dir)) return { schedules: [] };

  const files = readdirSync(dir).filter((f) => f.endsWith(".json"));
  const schedules: ScheduledScan[] = files.map((file) => {
    const raw = readFileSync(join(dir, file), "utf8");
    return JSON.parse(raw) as ScheduledScan;
  });

  return { schedules };
}

export function deleteScheduledScan(scheduleId: string): DeleteScheduledScanResult {
  const dir = schedulesDir();
  const filePath = join(dir, `${scheduleId}.json`);
  if (!existsSync(filePath)) {
    throw new Error(
      `Schedule not found: no schedule with id "${scheduleId}". Use list_scheduled_scans to see available schedules.`
    );
  }
  unlinkSync(filePath);
  return { deleted: true };
}
