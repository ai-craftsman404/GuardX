#!/usr/bin/env node
/**
 * GuardX auto-scan hook
 *
 * Fires after Write or Edit tool use. Checks whether the modified file looks
 * like a system prompt — if so, prints a reminder to run /guardx:scan.
 *
 * Configured in .claude/settings.local.json under hooks.PostToolUse.
 * Receives a JSON payload on stdin describing the tool call that just ran.
 */

const chunks = [];
process.stdin.on("data", (d) => chunks.push(d));
process.stdin.on("end", () => {
  let payload;
  try {
    payload = JSON.parse(Buffer.concat(chunks).toString());
  } catch {
    // Not valid JSON — nothing to do
    process.exit(0);
  }

  const filePath = String(payload?.tool_input?.file_path ?? "");
  const content = String(
    payload?.tool_input?.content ??
    payload?.tool_input?.new_string ??
    ""
  );

  const isSystemPromptByPath =
    /system.?prompt/i.test(filePath) ||
    /\.sp\.(txt|md|json)$/i.test(filePath) ||
    /system[-_]?prompt\.(txt|md|json|ts|js)$/i.test(filePath);

  const isSystemPromptByContent =
    content.length > 50 &&
    /\b(you are|your role|your task|your purpose|assistant instructions|system instructions|rules:|constraints:)/i.test(
      content.slice(0, 800)
    );

  if (isSystemPromptByPath || isSystemPromptByContent) {
    const label = filePath ? `\`${filePath}\`` : "the modified file";
    process.stdout.write(
      `[GuardX] System prompt detected in ${label}. ` +
        `Run /guardx:scan to check for prompt injection and extraction vulnerabilities.\n`
    );
  }

  process.exit(0);
});
