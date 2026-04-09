import { readFileSync, writeFileSync, existsSync, readdirSync } from "fs";
import { join, basename } from "path";
import { runSecurityScan } from "zeroleaks";
import {
  ScheduledScan,
  computeNextRunAt,
  buildWebhookPayload,
  shouldTriggerWebhook,
} from "./scheduler.js";
import { saveScan } from "./history.js";

const SCHEDULES_DIR =
  process.env.GUARDX_SCHEDULES_DIR ?? join(process.cwd(), ".guardx", "schedules");

const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY ?? "";

export async function runScheduler(schedulesDir?: string): Promise<void> {
  const dir = schedulesDir ?? SCHEDULES_DIR;
  if (!existsSync(dir)) return;

  const files = readdirSync(dir).filter((f) => f.endsWith(".json"));
  const now = new Date();

  for (const file of files) {
    const filePath = join(dir, file);
    let schedule: ScheduledScan;

    try {
      schedule = JSON.parse(readFileSync(filePath, "utf8")) as ScheduledScan;
    } catch {
      continue;
    }

    if (schedule.status !== "active") continue;
    if (new Date(schedule.nextRunAt) > now) continue;

    // Resolve system prompt
    let systemPrompt: string;
    if (schedule.promptFile) {
      try {
        systemPrompt = readFileSync(schedule.promptFile, "utf8");
      } catch {
        schedule.lastRunAt = new Date().toISOString();
        schedule.lastResult = "error";
        schedule.nextRunAt = computeNextRunAt(schedule.cronExpression);
        writeFileSync(filePath, JSON.stringify(schedule, null, 2));
        continue;
      }
    } else {
      systemPrompt = schedule.systemPrompt ?? "";
    }

    try {
      const mode = schedule.mode ?? "dual";
      const scanOptions: Parameters<typeof runSecurityScan>[1] = {
        apiKey: OPENROUTER_API_KEY,
      };
      if (schedule.attackerModel) scanOptions.attackerModel = schedule.attackerModel;
      if (schedule.targetModel) scanOptions.targetModel = schedule.targetModel;
      if (schedule.evaluatorModel) scanOptions.evaluatorModel = schedule.evaluatorModel;

      if (mode === "dual") {
        scanOptions.enableDualMode = true;
      } else if (mode === "extraction") {
        scanOptions.scanMode = "extraction";
        scanOptions.enableDualMode = false;
      } else if (mode === "injection") {
        scanOptions.scanMode = "injection";
        scanOptions.enableDualMode = false;
      }

      const result = await runSecurityScan(systemPrompt, scanOptions);
      const resultRecord = result as Record<string, unknown>;

      // Save to history (failure must not break the runner)
      let scanId: string | undefined;
      try {
        scanId = saveScan(resultRecord, systemPrompt);
      } catch {
        // intentionally swallowed
      }

      const findings = (resultRecord.findings as unknown[]) ?? [];

      // Trigger webhook if warranted
      if (schedule.webhookUrl && findings.length > 0) {
        const triggeredFindings = findings.filter((f) => {
          const finding = f as Record<string, unknown>;
          const severity = typeof finding.severity === "string" ? finding.severity : "";
          return shouldTriggerWebhook(severity, schedule.webhookOnSeverity);
        });

        if (triggeredFindings.length > 0) {
          const payload = buildWebhookPayload({
            scheduleId: schedule.scheduleId,
            scheduleName: schedule.name,
            regressionCount: triggeredFindings.length,
            newFindings: triggeredFindings,
            scanId: scanId ?? "",
            scannedAt: new Date().toISOString(),
            reportUrl: scanId ? `.guardx/reports/${scanId}.html` : "",
          });

          try {
            await fetch(schedule.webhookUrl, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(payload),
            });
          } catch {
            // webhook failure must not break the runner
          }
        }
      }

      const isClean = findings.length === 0;

      schedule.lastRunAt = new Date().toISOString();
      schedule.lastResult = isClean ? "clean" : "regression";
      schedule.nextRunAt = computeNextRunAt(schedule.cronExpression);
      writeFileSync(filePath, JSON.stringify(schedule, null, 2));
    } catch {
      schedule.lastRunAt = new Date().toISOString();
      schedule.lastResult = "error";
      schedule.nextRunAt = computeNextRunAt(schedule.cronExpression);
      writeFileSync(filePath, JSON.stringify(schedule, null, 2));
    }
  }
}

// Standalone entry — run when invoked as `node dist/scheduler-runner.js`
if (
  process.argv[1] &&
  basename(process.argv[1]).replace(/\.ts$/, ".js") === "scheduler-runner.js"
) {
  runScheduler().catch(console.error);
}
