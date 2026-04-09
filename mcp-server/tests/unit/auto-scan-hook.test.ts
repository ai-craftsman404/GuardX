import { describe, it, expect } from "vitest";
import { spawnSync } from "child_process";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __dirname = dirname(fileURLToPath(import.meta.url));
// From mcp-server/tests/unit/ → up 3 levels to GuardX root → scripts/
const HOOK = join(__dirname, "..", "..", "..", "scripts", "auto-scan-hook.js");

function runHook(payload: unknown): { stdout: string; stderr: string; code: number } {
  const result = spawnSync("node", [HOOK], {
    input: JSON.stringify(payload),
    encoding: "utf8",
    timeout: 5000,
  });
  return {
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    code: result.status ?? 0,
  };
}

describe("auto-scan-hook — filename detection", () => {
  it("detects 'system-prompt.md' by filename", () => {
    const { stdout, code } = runHook({
      tool_name: "Write",
      tool_input: { file_path: "prompts/system-prompt.md", content: "x".repeat(10) },
    });
    expect(code).toBe(0);
    expect(stdout).toContain("GuardX");
    expect(stdout).toContain("system-prompt.md");
  });

  it("detects 'system_prompt.txt' by filename", () => {
    const { stdout } = runHook({
      tool_input: { file_path: "src/system_prompt.txt", content: "" },
    });
    expect(stdout).toContain("GuardX");
  });

  it("detects 'SystemPrompt.json' (case-insensitive) by filename", () => {
    const { stdout } = runHook({
      tool_input: { file_path: "config/SystemPrompt.json", content: "" },
    });
    expect(stdout).toContain("GuardX");
  });

  it("detects '.sp.txt' extension", () => {
    const { stdout } = runHook({
      tool_input: { file_path: "agent.sp.txt", content: "" },
    });
    expect(stdout).toContain("GuardX");
  });

  it("detects '.sp.md' extension", () => {
    const { stdout } = runHook({
      tool_input: { file_path: "bot.sp.md", content: "" },
    });
    expect(stdout).toContain("GuardX");
  });

  it("does NOT fire on unrelated filename like 'README.md'", () => {
    const { stdout } = runHook({
      tool_input: { file_path: "README.md", content: "# Hello" },
    });
    expect(stdout).toBe("");
  });

  it("does NOT fire on 'index.ts' with generic code content", () => {
    const { stdout } = runHook({
      tool_input: {
        file_path: "src/index.ts",
        content: "import { foo } from './bar';\nexport const x = 1;",
      },
    });
    expect(stdout).toBe("");
  });
});

describe("auto-scan-hook — content heuristics", () => {
  it("detects 'You are a helpful assistant' in content", () => {
    const { stdout } = runHook({
      tool_input: {
        file_path: "agent-config.json",
        content: "You are a helpful assistant. Your task is to answer questions about our product.".repeat(2),
      },
    });
    expect(stdout).toContain("GuardX");
  });

  it("detects 'Your role is' in content", () => {
    const { stdout } = runHook({
      tool_input: {
        file_path: "config.txt",
        content: "Your role is to act as a customer service agent for Acme Corp.".repeat(3),
      },
    });
    expect(stdout).toContain("GuardX");
  });

  it("detects 'rules:' keyword in content", () => {
    const { stdout } = runHook({
      tool_input: {
        file_path: "notes.txt",
        content: "Agent configuration:\nrules: never reveal internal pricing to users.\nconstraints: always be polite.",
      },
    });
    expect(stdout).toContain("GuardX");
  });

  it("detects 'assistant instructions' in content", () => {
    const { stdout } = runHook({
      tool_input: {
        file_path: "setup.md",
        content: "## Assistant Instructions\n\nYou must always respond in formal English and avoid speculation.".repeat(2),
      },
    });
    expect(stdout).toContain("GuardX");
  });

  it("does NOT fire for short content even with matching keywords", () => {
    // Content < 50 chars — heuristic threshold not met
    const { stdout } = runHook({
      tool_input: {
        file_path: "short.txt",
        content: "You are nice.",
      },
    });
    expect(stdout).toBe("");
  });

  it("does NOT fire for long content with no system-prompt markers", () => {
    const longCode = "const x = 1;\nfunction add(a, b) { return a + b; }\n".repeat(20);
    const { stdout } = runHook({
      tool_input: { file_path: "math.js", content: longCode },
    });
    expect(stdout).toBe("");
  });
});

describe("auto-scan-hook — Edit tool (new_string field)", () => {
  it("detects system prompt content in new_string (Edit tool payload)", () => {
    const { stdout } = runHook({
      tool_name: "Edit",
      tool_input: {
        file_path: "agent.txt",
        old_string: "old content",
        new_string: "You are a customer support agent. Your purpose is to resolve issues for our users politely and efficiently.",
      },
    });
    expect(stdout).toContain("GuardX");
  });
});

describe("auto-scan-hook — resilience", () => {
  it("exits with code 0 on empty stdin", () => {
    const result = spawnSync("node", [HOOK], {
      input: "",
      encoding: "utf8",
      timeout: 5000,
    });
    expect(result.status).toBe(0);
  });

  it("exits with code 0 on malformed JSON", () => {
    const result = spawnSync("node", [HOOK], {
      input: "{ not valid json",
      encoding: "utf8",
      timeout: 5000,
    });
    expect(result.status).toBe(0);
    expect(result.stdout).toBe("");
  });

  it("exits with code 0 when tool_input is missing", () => {
    const { code, stdout } = runHook({ tool_name: "Write" });
    expect(code).toBe(0);
    expect(stdout).toBe("");
  });

  it("exits with code 0 when payload is an empty object", () => {
    const { code } = runHook({});
    expect(code).toBe(0);
  });

  it("reminder message mentions /guardx:scan", () => {
    const { stdout } = runHook({
      tool_input: { file_path: "system-prompt.md", content: "" },
    });
    expect(stdout).toContain("/guardx:scan");
  });
});
