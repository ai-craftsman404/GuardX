import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { runSecurityScan } from "./scanner.js";
import { getAllProbes, getProbesByCategory, DOCUMENTED_TECHNIQUES } from "./probes.js";
import { saveScan, listHistory, getHistoryScan } from "./history.js";
import { generateHtml, generateSarif, generateJunit, generatePdf } from "./reports.js";
import { generateCanary, checkCanary, saveCanary, listCanaries } from "./canary.js";
import { runRedTeam } from "./redteam.js";
import { enrichFindings } from "./compliance.js";
import { generateGuardrails } from "./guardrails.js";
import { scanEndpoint } from "./endpoint.js";
import { diffScans } from "./diff.js";
import { testToolExfiltration } from "./toolcall.js";
import { testMultimodalInjection } from "./multimodal.js";
import { scanExtendedProbes } from "./probes-extended.js";
import { testMcpSecurity, auditMcpConfig } from "./mcpsecurity.js";
import { createScheduledScan, listScheduledScans, deleteScheduledScan } from "./scheduler.js";
import { testRagSecurity } from "./rag.js";
import { testAgentEscalation } from "./agentescalation.js";
import { scanSupplyChain } from "./supplychain.js";
import { simulatePromptwareKillchain } from "./promptware.js";
import { testDataPoisoning } from "./poisoning.js";
import { testAgentChain } from "./agentchain.js";
import { runCrossProviderScan } from "./crossprovider.js";
import { generateAuditReport } from "./audit-report.js";
import { generateTrendDashboard } from "./dashboard.js";
import { syncJailbreakFeed } from "./jailbreakfeed.js";

function getApiKey(): string {
  const key = process.env.OPENROUTER_API_KEY;
  if (!key) {
    throw new Error(
      "Missing required environment variable: OPENROUTER_API_KEY\n" +
        "Set it in your .env file or shell environment before starting the GuardX MCP server.\n" +
        "See .env.example for the required format."
    );
  }
  return key;
}


const DEFAULT_ATTACKER_MODEL = "anthropic/claude-sonnet-4.6";
const DEFAULT_TARGET_MODEL = "anthropic/claude-sonnet-4.6";
const DEFAULT_EVALUATOR_MODEL = "anthropic/claude-sonnet-4.6";
const DEFAULT_MAX_TURNS = 15;

export const TOOL_DEFINITIONS = [
  {
    name: "scan_system_prompt",
    description:
      "Run a full security scan on a system prompt to test for prompt injection and extraction vulnerabilities. Returns findings, vulnerability rating, defense profile, and remediation recommendations. The result is automatically saved to scan history.",
    inputSchema: {
      type: "object",
      properties: {
        systemPrompt: {
          type: "string",
          description: "The system prompt text to scan for vulnerabilities.",
        },
        mode: {
          type: "string",
          enum: ["extraction", "injection", "dual"],
          description:
            "Scan mode: 'extraction' tests for system prompt leakage, 'injection' tests for malicious input injection, 'dual' runs both (default: 'dual').",
        },
        maxTurns: {
          type: "number",
          description:
            "Maximum number of attack turns per scan (default: 15).",
        },
        attackerModel: {
          type: "string",
          description:
            "OpenRouter model ID for the attacker agent (default: anthropic/claude-3-5-sonnet).",
        },
        targetModel: {
          type: "string",
          description:
            "OpenRouter model ID for the target being scanned (default: anthropic/claude-3-5-sonnet).",
        },
        evaluatorModel: {
          type: "string",
          description:
            "OpenRouter model ID for the evaluator agent (default: anthropic/claude-3-5-sonnet).",
        },
      },
      required: ["systemPrompt"],
    },
  },
  {
    name: "list_probes",
    description:
      "List available attack probes from the ZeroLeaks probe catalogue, optionally filtered by attack category.",
    inputSchema: {
      type: "object",
      properties: {
        category: {
          type: "string",
          enum: [
            "direct",
            "encoding",
            "persona",
            "social",
            "technical",
            "crescendo",
            "many_shot",
            "ascii_art",
            "cot_hijack",
            "semantic_shift",
            "policy_puppetry",
            "context_overflow",
            "reasoning_exploit",
            "hybrid",
            "tool_exploit",
            "siren",
            "echo_chamber",
            "injection",
          ],
          description:
            "Filter probes by attack category. If omitted, returns all probes.",
        },
      },
    },
  },
  {
    name: "list_techniques",
    description:
      "Return the documented attack techniques knowledge base — descriptions, categories, and known success rates for all known LLM attack techniques.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "get_scan_config",
    description:
      "Return available scan configuration options including default models, scan modes, and parameter ranges.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "list_scan_history",
    description:
      "List previously saved scan results with metadata: scan ID, date, vulnerability rating, leak status, prompt hash, and finding count. Results are ordered newest first.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "get_scan_result",
    description:
      "Retrieve a full previously saved scan result by its ID (from list_scan_history).",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description:
            "Scan ID as returned by list_scan_history or included in a scan_system_prompt response.",
        },
      },
      required: ["id"],
    },
  },
  {
    name: "generate_report",
    description:
      "Generate an HTML, SARIF 2.1.0, or JUnit XML report for a scan result. Pass a scan ID to load from history, or pass a full result object directly. The report file is written to .guardx/reports/ and the file path is returned.",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description:
            "Scan ID from list_scan_history. If provided, loads the scan from history.",
        },
        result: {
          type: "object",
          description:
            "Full ScanResult object. Used when id is not provided (e.g. for a fresh scan result).",
        },
        format: {
          type: "string",
          enum: ["html", "sarif", "junit", "pdf"],
          description:
            "Report format. 'html' produces a self-contained HTML report; 'sarif' produces SARIF 2.1.0 for GitHub Security tab integration; 'junit' produces JUnit XML for Jenkins, SonarQube, and Azure DevOps; 'pdf' produces a PDF report for leadership briefings and compliance audit sign-off. Default: 'html'.",
        },
      },
    },
  },
  {
    name: "inject_canary",
    description:
      "Embed a unique traceable canary token into a system prompt. If an attacker extracts the prompt and the token appears in output, it proves real leakage. Returns the modified prompt ready to deploy.",
    inputSchema: {
      type: "object",
      properties: {
        systemPrompt: {
          type: "string",
          description: "The system prompt text to embed the canary token into.",
        },
        label: {
          type: "string",
          description: "Optional label to identify this canary (default: 'unlabelled').",
        },
        embeddingStyle: {
          type: "string",
          enum: ["comment", "echo-instruction"],
          description:
            "'echo-instruction' embeds a command that forces the model to repeat the token in every response — more resilient to paraphrasing. 'comment' uses a simple inline reference. Default: 'echo-instruction'.",
        },
      },
      required: ["systemPrompt"],
    },
  },
  {
    name: "check_canary",
    description:
      "Check whether a canary token appears in a scan result's extracted content, indicating real prompt leakage occurred.",
    inputSchema: {
      type: "object",
      properties: {
        token: {
          type: "string",
          description: "The canary token to search for (e.g. 'GX-a1b2c3d4').",
        },
        id: {
          type: "string",
          description: "Scan history ID — loads the scan result from history.",
        },
        result: {
          type: "object",
          description: "Inline ScanResult object. Used when id is not provided.",
        },
      },
      required: ["token"],
    },
  },
  {
    name: "list_canaries",
    description:
      "List all injected canary tokens, newest first.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "run_red_team",
    description:
      "Run a multi-phase adaptive red team attack on a system prompt. More aggressive than a standard scan — adapts strategy based on findings. Strategy: 'blitz' (fast, 1 phase), 'thorough' (3 phases, ~5 min), 'stealth' (slow, mimics real attacker). Result is auto-saved to history.",
    inputSchema: {
      type: "object",
      properties: {
        systemPrompt: {
          type: "string",
          description: "The system prompt to red team.",
        },
        strategy: {
          type: "string",
          enum: ["blitz", "thorough", "stealth", "goal-hijack"],
          description: "Attack strategy (default: 'thorough'). 'goal-hijack' tests agent objective manipulation.",
        },
        maxPhases: {
          type: "number",
          description: "Maximum number of phases to run (strategy-dependent).",
        },
        attackerModel: {
          type: "string",
          description: "OpenRouter model ID for the attacker agent.",
        },
        targetModel: {
          type: "string",
          description: "OpenRouter model ID for the target being scanned.",
        },
        evaluatorModel: {
          type: "string",
          description: "OpenRouter model ID for the evaluator agent.",
        },
      },
      required: ["systemPrompt"],
    },
  },
  {
    name: "map_findings",
    description:
      "Tag scan findings with OWASP LLM Top 10 2025, NIST AI RMF, MITRE ATLAS, and EU AI Act framework references. Returns enriched findings plus a compliance summary.",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "Scan history ID to load findings from.",
        },
        result: {
          type: "object",
          description: "Inline ScanResult object. Used when id is not provided.",
        },
      },
    },
  },
  {
    name: "generate_guardrails",
    description:
      "Analyse scan findings and generate concrete prompt hardening text that closes the exact vulnerabilities found. Returns the hardened prompt with added security guardrails.",
    inputSchema: {
      type: "object",
      properties: {
        originalPrompt: {
          type: "string",
          description: "The original system prompt to harden.",
        },
        id: {
          type: "string",
          description: "Scan history ID to load findings from.",
        },
        result: {
          type: "object",
          description: "Inline ScanResult object. Used when id is not provided.",
        },
      },
      required: ["originalPrompt"],
    },
  },
  {
    name: "scan_endpoint",
    description:
      "Scan a live HTTP endpoint by sending attack probes as real HTTP requests and evaluating responses for leakage or injection. Supports any endpoint: deployed chatbot API, LangChain app, RAG pipeline, Ollama. Result is auto-saved to history.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "The endpoint URL to scan.",
        },
        method: {
          type: "string",
          enum: ["POST", "GET"],
          description: "HTTP method (default: 'POST').",
        },
        headers: {
          type: "object",
          description: "Optional HTTP headers (e.g. Authorization).",
        },
        requestTemplate: {
          type: "string",
          description: "JSON request body template containing {{PROBE}} placeholder, e.g. '{\"message\":\"{{PROBE}}\"}'.",
        },
        responseField: {
          type: "string",
          description: "Dot-notation path to extract text from JSON response, e.g. 'choices.0.message.content'. Defaults to full response body.",
        },
        timeoutMs: {
          type: "number",
          description: "Request timeout in milliseconds (default: 30000).",
        },
        mode: {
          type: "string",
          enum: ["extraction", "injection", "dual"],
          description: "Scan mode (default: 'dual').",
        },
        maxTurns: {
          type: "number",
          description: "Maximum number of probes to send (default: 15).",
        },
        attackerModel: {
          type: "string",
          description: "OpenRouter model ID for the attacker agent.",
        },
        evaluatorModel: {
          type: "string",
          description: "OpenRouter model ID for the evaluator agent.",
        },
      },
      required: ["url", "requestTemplate"],
    },
  },
  {
    name: "diff_scans",
    description:
      "Compare a current scan against a previous baseline scan. Returns only newly introduced vulnerabilities (regressions), resolved findings, and persisting issues — ideal for PR-level checks where you only care about what changed.",
    inputSchema: {
      type: "object",
      properties: {
        baselineScanId: {
          type: "string",
          description: "ID of the previous baseline scan (the 'before').",
        },
        currentScanId: {
          type: "string",
          description: "ID of the new scan to compare against the baseline. Mutually exclusive with systemPrompt.",
        },
        systemPrompt: {
          type: "string",
          description: "Run a fresh scan and diff against the baseline. Mutually exclusive with currentScanId.",
        },
        mode: {
          type: "string",
          enum: ["extraction", "injection", "dual"],
          description: "Scan mode for fresh scan (only used when systemPrompt is provided). Default: 'dual'.",
        },
      },
      required: ["baselineScanId"],
    },
  },
  {
    name: "test_tool_exfiltration",
    description:
      "Test whether injected instructions can manipulate an agent into calling dangerous tools or leaking data via tool arguments. Tests 5 attack patterns: direct exfil, indirect exfil, argument injection, goal hijacking, and schema manipulation.",
    inputSchema: {
      type: "object",
      properties: {
        systemPrompt: {
          type: "string",
          description: "The system prompt of the agent to test.",
        },
        availableTools: {
          type: "array",
          description: "Array of tool definitions the agent has access to (name, description, parameters).",
          items: { type: "object" },
        },
        targetDataPatterns: {
          type: "array",
          description: "Patterns to look for in tool arguments (e.g. ['system prompt', 'instructions']). Defaults to common system prompt keywords.",
          items: { type: "string" },
        },
        maxTurns: {
          type: "number",
          description: "Maximum number of attack probes to run (default: 10).",
        },
      },
      required: ["systemPrompt", "availableTools"],
    },
  },
  {
    name: "test_multimodal_injection",
    description:
      "Test vision-capable LLMs for image-based prompt injection — adversarial instructions embedded in images that override the system prompt. Tests 4 injection styles: text overlay, low contrast, structured prompt, and QR code.",
    inputSchema: {
      type: "object",
      properties: {
        systemPrompt: {
          type: "string",
          description: "The system prompt of the vision-capable agent to test.",
        },
        targetModel: {
          type: "string",
          description: "Vision-capable model to test (e.g. gpt-4o, claude-3-5-sonnet, claude-opus-4-6).",
        },
        injectionStyles: {
          type: "array",
          description: "Subset of injection styles to test. Default: all styles (text_overlay, low_contrast, structured_prompt, qr_code).",
          items: {
            type: "string",
            enum: ["text_overlay", "low_contrast", "structured_prompt", "qr_code"],
          },
        },
      },
      required: ["systemPrompt", "targetModel"],
    },
  },
  {
    name: "scan_extended_probes",
    description:
      "Run extended attack probe techniques against a system prompt: FlipAttack (character/word reversal that bypasses safety classifiers), PAP (Persuasive Adversarial Prompts using social manipulation), and Roleplay-Based Jailbreaks (fictional framing). Returns per-technique success rates and overall vulnerability rating.",
    inputSchema: {
      type: "object",
      properties: {
        systemPrompt: {
          type: "string",
          description: "The system prompt to test.",
        },
        techniques: {
          type: "array",
          description: "Techniques to run. Default: all three (flipattack, pap, roleplay).",
          items: {
            type: "string",
            enum: ["flipattack", "pap", "roleplay", "serialization-rce"],
          },
        },
        attackerModel: {
          type: "string",
          description: "OpenRouter model ID for attacker/target calls.",
        },
        evaluatorModel: {
          type: "string",
          description: "OpenRouter model ID for evaluation calls.",
        },
        maxAttemptsPerTechnique: {
          type: "number",
          description: "Maximum attack attempts per technique (default: 5).",
        },
      },
      required: ["systemPrompt"],
    },
  },
  {
    name: "test_mcp_security",
    description:
      "Test the MCP server layer for security vulnerabilities: tool description poisoning, credential/environment exfiltration via tool arguments, tool invocation hijacking, and schema confusion attacks.",
    inputSchema: {
      type: "object",
      properties: {
        systemPrompt: {
          type: "string",
          description: "The system prompt of the agent to test.",
        },
        mcpToolSchemas: {
          type: "array",
          description: "The MCP tool definitions exposed to Claude (name, description, inputSchema).",
          items: { type: "object" },
        },
        sensitivePatterns: {
          type: "array",
          description: "Keywords to look for in tool arguments (default: ['API_KEY', 'SECRET', 'TOKEN', 'PASSWORD']).",
          items: { type: "string" },
        },
        attackerModel: {
          type: "string",
          description: "OpenRouter model ID for attacker calls.",
        },
        evaluatorModel: {
          type: "string",
          description: "OpenRouter model ID for evaluation calls.",
        },
      },
      required: ["systemPrompt", "mcpToolSchemas"],
    },
  },
  {
    name: "create_scheduled_scan",
    description:
      "Register a cron-scheduled automatic re-scan of a system prompt. On each run the result is compared against the previous scan; if a regression is detected a webhook notification fires.",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description: "Human-readable label for this schedule (e.g. 'Production chatbot daily scan').",
        },
        systemPrompt: {
          type: "string",
          description: "Inline system prompt text to scan. Mutually exclusive with promptFile.",
        },
        promptFile: {
          type: "string",
          description: "Path to a file containing the system prompt. Mutually exclusive with systemPrompt.",
        },
        cronExpression: {
          type: "string",
          description: "5-field cron expression (e.g. '0 9 * * *' = every day at 9am).",
        },
        mode: {
          type: "string",
          enum: ["extraction", "injection", "dual"],
          description: "Scan mode (default: 'dual').",
        },
        webhookUrl: {
          type: "string",
          description: "URL to POST to when a regression is detected.",
        },
        webhookOnSeverity: {
          type: "array",
          description: "Severity levels that trigger the webhook (default: ['critical', 'high']).",
          items: { type: "string", enum: ["critical", "high", "medium", "low"] },
        },
        attackerModel: { type: "string" },
        targetModel: { type: "string" },
        evaluatorModel: { type: "string" },
      },
      required: ["name", "cronExpression"],
    },
  },
  {
    name: "list_scheduled_scans",
    description: "List all registered scheduled scans with their status, last/next run times, and last result.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "delete_scheduled_scan",
    description: "Remove a scheduled scan by its ID.",
    inputSchema: {
      type: "object",
      properties: {
        scheduleId: {
          type: "string",
          description: "The schedule ID to delete (from list_scheduled_scans).",
        },
      },
      required: ["scheduleId"],
    },
  },
  {
    name: "test_rag_security",
    description:
      "Test a RAG-based LLM system for corpus poisoning and data exfiltration vulnerabilities. Runs 6 attack categories (encoding, structural, semantic, layered, trigger, exfiltration) with 15 techniques including the full PyRIT EX1-EX5 exfiltration taxonomy.",
    inputSchema: {
      type: "object",
      properties: {
        systemPrompt: {
          type: "string",
          description: "The system prompt of the RAG-based LLM to test.",
        },
        retrievalEndpoint: {
          type: "string",
          description: "Optional HTTP endpoint for real retrieval testing.",
        },
        categories: {
          type: "array",
          description: "Attack categories to run. Default: all 6 (encoding, structural, semantic, layered, trigger, exfiltration).",
          items: {
            type: "string",
            enum: ["encoding", "structural", "semantic", "layered", "trigger", "exfiltration"],
          },
        },
        targetModel: {
          type: "string",
          description: "OpenRouter model ID for the target LLM.",
        },
        evaluatorModel: {
          type: "string",
          description: "OpenRouter model ID for the evaluator.",
        },
        maxDocumentsPerAttack: {
          type: "number",
          description: "Maximum poisoned documents per technique (default: 3).",
        },
      },
      required: ["systemPrompt"],
    },
  },
  {
    name: "test_agent_escalation",
    description:
      "Simulate the 5-step inter-agent privilege escalation kill chain. Tests whether a low-privilege agent can be manipulated into requesting a high-privilege agent to perform an unauthorised action.",
    inputSchema: {
      type: "object",
      properties: {
        agentHierarchy: {
          type: "array",
          description: "Array of AgentRole objects defining agent names, privilege levels (1-10), system prompts, and delegation rights.",
          items: { type: "object" },
        },
        sharedDataStore: {
          type: "string",
          description: "Optional data accessible to the low-privilege agent (simulates poisoned shared storage).",
        },
        targetCapability: {
          type: "string",
          description: "The unauthorised action the attacker wants the high-privilege agent to perform.",
        },
        attackerModel: {
          type: "string",
          description: "OpenRouter model ID for agent simulation calls.",
        },
        evaluatorModel: {
          type: "string",
          description: "OpenRouter model ID for escalation evaluation.",
        },
        maxChainDepth: {
          type: "number",
          description: "Maximum number of escalation hops to attempt (default: 3).",
        },
      },
      required: ["agentHierarchy", "targetCapability"],
    },
  },
  {
    name: "scan_supply_chain",
    description:
      "Scan LLM project dependencies, model config files, and LoRA adapter weight files for known CVEs (including CVE-2026-33634 LiteLLM supply chain attack), embedded secrets, and weight-space backdoor anomalies.",
    inputSchema: {
      type: "object",
      properties: {
        projectPath: {
          type: "string",
          description: "Path to project root containing package.json or requirements.txt.",
        },
        scanLoraAdapters: {
          type: "array",
          description: "Optional paths to LoRA adapter weight files for backdoor detection.",
          items: { type: "string" },
        },
        scanModelConfigs: {
          type: "array",
          description: "Optional paths to model config JSON/YAML files.",
          items: { type: "string" },
        },
        checkCves: {
          type: "boolean",
          description: "Check dependencies against CVE database (default: true).",
        },
        checkSecrets: {
          type: "boolean",
          description: "Scan for embedded API keys and tokens (default: true).",
        },
        checkBackdoors: {
          type: "boolean",
          description: "Analyse LoRA adapter weight statistics for anomalies (default: true).",
        },
      },
      required: ["projectPath"],
    },
  },
  {
    name: "audit_mcp_config",
    description:
      "Scan MCP project configuration for privilege escalation, tool description poisoning, SSRF patterns, and rogue servers. Detects misconfigurations that could enable LLM attacks.",
    inputSchema: {
      type: "object",
      properties: {
        configPath: {
          type: "string",
          description: "Path to the MCP configuration file to audit.",
        },
        checkPrivilegeModel: {
          type: "boolean",
          description: "Check for privilege model vulnerabilities (default: true).",
        },
        checkToolDescriptions: {
          type: "boolean",
          description: "Check tool descriptions for poisoning keywords (default: true).",
        },
      },
      required: ["configPath"],
    },
  },
  {
    name: "simulate_promptware_killchain",
    description:
      "Simulate a 4-stage prompt injection kill chain: inject malicious instructions, trigger tool calls, exfiltrate data, and pivot to secondary systems. Evaluates whether all stages can succeed.",
    inputSchema: {
      type: "object",
      properties: {
        systemPrompt: {
          type: "string",
          description: "The system prompt to test.",
        },
        availableTools: {
          type: "array",
          description: "Array of tool definitions available to the target agent.",
          items: {
            type: "object",
            properties: {
              name: { type: "string" },
              description: { type: "string" },
            },
            required: ["name"],
          },
        },
        targetData: {
          type: "string",
          description: "Data the attacker wants to exfiltrate (defaults to systemPrompt).",
        },
        stages: {
          type: "array",
          description: "Stages to simulate. Default: all 4 (inject, trigger, exfiltrate, pivot).",
          items: { type: "string", enum: ["inject", "trigger", "exfiltrate", "pivot"] },
        },
        attackerModel: {
          type: "string",
          description: "OpenRouter model ID for the attacker agent.",
        },
        targetModel: {
          type: "string",
          description: "OpenRouter model ID for the target agent.",
        },
        evaluatorModel: {
          type: "string",
          description: "OpenRouter model ID for the evaluator agent.",
        },
      },
      required: ["systemPrompt", "availableTools"],
    },
  },
  {
    name: "test_data_poisoning",
    description:
      "Test training data for poisoning attacks including character substitution, adversarial examples, data integrity issues, and backdoors. Returns risk assessment and detected poisoning patterns.",
    inputSchema: {
      type: "object",
      properties: {
        data: {
          type: "string",
          description: "Training data or text to analyze for poisoning attacks.",
        },
      },
      required: ["data"],
    },
  },
  {
    name: "test_agent_chain",
    description:
      "Test agent chain architectures for token passing attacks, message injection, privilege escalation, and trust boundary violations. Evaluates multi-agent system security.",
    inputSchema: {
      type: "object",
      properties: {
        chain: {
          type: "string",
          description: "Description of agent chain interactions to analyze.",
        },
      },
      required: ["chain"],
    },
  },
  {
    name: "test_cross_provider_consistency",
    description:
      "Test response consistency across multiple LLM providers to detect jailbreak vulnerabilities that work on some providers but not others.",
    inputSchema: {
      type: "object",
      properties: {
        responses: {
          type: "object",
          description: "Provider responses object with isSafe boolean values.",
        },
      },
      required: ["responses"],
    },
  },
  {
    name: "generate_audit_report",
    description:
      "Export security audit findings in JSON, CSV, or PDF format for compliance and reporting.",
    inputSchema: {
      type: "object",
      properties: {
        format: {
          type: "string",
          enum: ["json", "csv", "pdf"],
          description: "Export format (default: json).",
        },
      },
    },
  },
  {
    name: "generate_trend_dashboard",
    description:
      "Generate dashboard showing vulnerability trends over time and top security risks.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "track_jailbreak_feed",
    description:
      "Track latest jailbreak techniques, success rates, and discovery dates from the security research community.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
];

export async function handleToolCall(
  name: string,
  args: Record<string, unknown>
): Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }> {
  if (name === "scan_system_prompt") {
    if (!args || typeof args.systemPrompt !== "string" || !args.systemPrompt.trim()) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: systemPrompt must be a non-empty string." }) }],
        isError: true,
      };
    }
    const mode = (args.mode as string) ?? "dual";
    const maxTurns = (args.maxTurns as number) ?? DEFAULT_MAX_TURNS;
    const attackerModel = (args.attackerModel as string) ?? DEFAULT_ATTACKER_MODEL;
    const targetModel = (args.targetModel as string) ?? DEFAULT_TARGET_MODEL;
    const evaluatorModel = (args.evaluatorModel as string) ?? DEFAULT_EVALUATOR_MODEL;

    const scanOptions: Parameters<typeof runSecurityScan>[1] = {
      ...(mode === "dual"
        ? { enableDualMode: true }
        : { scanMode: mode as "extraction" | "injection", enableDualMode: false }),
      maxTurns,
      attackerModel,
      targetModel,
      evaluatorModel,
    };
    try {
      const result = await runSecurityScan(args.systemPrompt as string, scanOptions);

      let scanId: string | undefined;
      try {
        scanId = saveScan(result as unknown as Record<string, unknown>, args.systemPrompt as string);
      } catch {
        // History save failure must not break the scan response
      }

      return {
        content: [{
          type: "text",
          text: JSON.stringify({ scanId, ...result }, null, 2),
        }],
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: `Scan failed: ${message}` }) }],
        isError: true,
      };
    }
  }

  if (name === "list_probes") {
    const category = args?.category as string | undefined;
    const probes = category
      ? getProbesByCategory(category as Parameters<typeof getProbesByCategory>[0])
      : getAllProbes();
    return { content: [{ type: "text", text: JSON.stringify(probes, null, 2) }] };
  }

  if (name === "list_techniques") {
    return { content: [{ type: "text", text: JSON.stringify(DOCUMENTED_TECHNIQUES, null, 2) }] };
  }

  if (name === "get_scan_config") {
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          defaults: { mode: "dual", maxTurns: DEFAULT_MAX_TURNS, attackerModel: DEFAULT_ATTACKER_MODEL, targetModel: DEFAULT_TARGET_MODEL, evaluatorModel: DEFAULT_EVALUATOR_MODEL },
          modes: ["extraction", "injection", "dual"],
          maxTurnsRange: { min: 1, max: 50 },
          provider: "OpenRouter",
          recommendedModels: ["anthropic/claude-3-5-sonnet", "anthropic/claude-3-haiku", "openai/gpt-4o", "openai/gpt-4o-mini"],
        }, null, 2),
      }],
    };
  }

  if (name === "list_scan_history") {
    const history = listHistory();
    return { content: [{ type: "text", text: JSON.stringify(history, null, 2) }] };
  }

  if (name === "get_scan_result") {
    if (!args?.id || typeof args.id !== "string") {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: id" }) }],
        isError: true,
      };
    }
    const scan = getHistoryScan(args.id as string);
    if (!scan) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: `No scan found with id: ${args.id}` }) }],
        isError: true,
      };
    }
    return { content: [{ type: "text", text: JSON.stringify(scan, null, 2) }] };
  }

  if (name === "generate_report") {
    const format = (args?.format as string) ?? "html";

    let scan: Record<string, unknown> | null = null;
    let outputId: string;

    if (args?.id && typeof args.id === "string") {
      scan = getHistoryScan(args.id as string);
      if (!scan) {
        return {
          content: [{ type: "text", text: JSON.stringify({ error: `No scan found with id: ${args.id}` }) }],
          isError: true,
        };
      }
      outputId = args.id as string;
    } else if (args?.result && typeof args.result === "object") {
      scan = args.result as Record<string, unknown>;
      outputId = `report-${Date.now()}`;
    } else {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Provide either id (to load from history) or result (a ScanResult object)." }) }],
        isError: true,
      };
    }

    try {
      let filePath: string;
      if (format === "sarif") {
        filePath = generateSarif(scan as Parameters<typeof generateSarif>[0], outputId);
      } else if (format === "junit") {
        filePath = generateJunit(scan as Parameters<typeof generateJunit>[0], outputId);
      } else if (format === "pdf") {
        filePath = await generatePdf(scan as Parameters<typeof generatePdf>[0], outputId);
      } else {
        filePath = generateHtml(scan as Parameters<typeof generateHtml>[0], outputId);
      }

      return {
        content: [{
          type: "text",
          text: JSON.stringify({ filePath, format, scanId: outputId }, null, 2),
        }],
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: `Report generation failed: ${message}` }) }],
        isError: true,
      };
    }
  }

  if (name === "inject_canary") {
    if (!args?.systemPrompt || typeof args.systemPrompt !== "string" || !args.systemPrompt.trim()) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: systemPrompt must be a non-empty string." }) }],
        isError: true,
      };
    }
    const label = typeof args.label === "string" ? args.label : "unlabelled";
    const embeddingStyle = (args.embeddingStyle as "comment" | "echo-instruction") ?? "echo-instruction";
    const { token, embeddedPrompt, embeddingStyle: usedStyle } = generateCanary(
      args.systemPrompt as string,
      label,
      embeddingStyle
    );
    const createdAt = new Date().toISOString();
    try {
      saveCanary({ token, label, createdAt, embeddingStyle: usedStyle });
    } catch {
      // save failure must not break the response
    }
    return {
      content: [{ type: "text", text: JSON.stringify({ token, embeddedPrompt, label, createdAt, embeddingStyle: usedStyle }, null, 2) }],
    };
  }

  if (name === "check_canary") {
    if (!args?.token || typeof args.token !== "string") {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: token" }) }],
        isError: true,
      };
    }
    let scanResult: Record<string, unknown> | null = null;
    if (args.id && typeof args.id === "string") {
      scanResult = getHistoryScan(args.id as string);
      if (!scanResult) {
        return {
          content: [{ type: "text", text: JSON.stringify({ error: `No scan found with id: ${args.id}` }) }],
          isError: true,
        };
      }
    } else if (args.result && typeof args.result === "object") {
      scanResult = args.result as Record<string, unknown>;
    } else {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Provide either id (to load from history) or result (a ScanResult object)." }) }],
        isError: true,
      };
    }
    const checkResult = checkCanary(args.token as string, scanResult);
    return {
      content: [{ type: "text", text: JSON.stringify({ ...checkResult, token: args.token }, null, 2) }],
    };
  }

  if (name === "list_canaries") {
    const canaries = listCanaries();
    return { content: [{ type: "text", text: JSON.stringify(canaries, null, 2) }] };
  }

  if (name === "run_red_team") {
    if (!args?.systemPrompt || typeof args.systemPrompt !== "string" || !args.systemPrompt.trim()) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: systemPrompt must be a non-empty string." }) }],
        isError: true,
      };
    }
    const strategy = (args.strategy as string) ?? "thorough";
    if (!["blitz", "thorough", "stealth", "goal-hijack"].includes(strategy)) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: `Unknown strategy: ${strategy}. Must be blitz, thorough, stealth, or goal-hijack.` }) }],
        isError: true,
      };
    }
    try {
      const result = await runRedTeam(args.systemPrompt as string, {
        strategy: strategy as "blitz" | "thorough" | "stealth" | "goal-hijack",
        maxPhases: args.maxPhases as number | undefined,
        attackerModel: args.attackerModel as string | undefined,
        targetModel: args.targetModel as string | undefined,
        evaluatorModel: args.evaluatorModel as string | undefined,
        targetCapability: args.targetCapability as string | undefined,
      });

      let scanId: string | undefined;
      try {
        scanId = saveScan(result as unknown as Record<string, unknown>, args.systemPrompt as string);
      } catch {
        // save failure must not break the response
      }

      return {
        content: [{ type: "text", text: JSON.stringify({ scanId, ...result }, null, 2) }],
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: `Red team failed: ${message}` }) }],
        isError: true,
      };
    }
  }

  if (name === "map_findings") {
    let scanResult: Record<string, unknown> | null = null;
    if (args?.id && typeof args.id === "string") {
      scanResult = getHistoryScan(args.id as string);
      if (!scanResult) {
        return {
          content: [{ type: "text", text: JSON.stringify({ error: `No scan found with id: ${args.id}` }) }],
          isError: true,
        };
      }
    } else if (args?.result && typeof args.result === "object") {
      scanResult = args.result as Record<string, unknown>;
    } else {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Provide either id (to load from history) or result (a ScanResult object)." }) }],
        isError: true,
      };
    }
    const enriched = enrichFindings(scanResult);
    return { content: [{ type: "text", text: JSON.stringify(enriched, null, 2) }] };
  }

  if (name === "generate_guardrails") {
    if (!args?.originalPrompt || typeof args.originalPrompt !== "string") {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: originalPrompt must be a non-empty string." }) }],
        isError: true,
      };
    }
    let scanResult: Record<string, unknown> | null = null;
    if (args.id && typeof args.id === "string") {
      scanResult = getHistoryScan(args.id as string);
      if (!scanResult) {
        return {
          content: [{ type: "text", text: JSON.stringify({ error: `No scan found with id: ${args.id}` }) }],
          isError: true,
        };
      }
    } else if (args.result && typeof args.result === "object") {
      scanResult = args.result as Record<string, unknown>;
    } else {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Provide either id (to load from history) or result (a ScanResult object)." }) }],
        isError: true,
      };
    }
    const guardrailResult = generateGuardrails(scanResult, args.originalPrompt as string);
    return { content: [{ type: "text", text: JSON.stringify(guardrailResult, null, 2) }] };
  }

  if (name === "scan_endpoint") {
    if (!args?.url || typeof args.url !== "string") {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: url" }) }],
        isError: true,
      };
    }
    if (!args?.requestTemplate || typeof args.requestTemplate !== "string") {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: requestTemplate" }) }],
        isError: true,
      };
    }
    try {
      const result = await scanEndpoint(
        {
          url: args.url as string,
          method: (args.method as "POST" | "GET") ?? "POST",
          headers: args.headers as Record<string, string> | undefined,
          requestTemplate: args.requestTemplate as string,
          responseField: args.responseField as string | undefined,
          timeoutMs: args.timeoutMs as number | undefined,
        },
        {
          mode: args.mode as "extraction" | "injection" | "dual" | undefined,
          maxTurns: args.maxTurns as number | undefined,
          apiKey: getApiKey(),
          attackerModel: args.attackerModel as string | undefined,
          evaluatorModel: args.evaluatorModel as string | undefined,
        }
      );

      let scanId: string | undefined;
      try {
        scanId = saveScan(result, args.url as string);
      } catch {
        // save failure must not break the response
      }

      return {
        content: [{ type: "text", text: JSON.stringify({ scanId, ...result }, null, 2) }],
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: `Endpoint scan failed: ${message}` }) }],
        isError: true,
      };
    }
  }

  if (name === "diff_scans") {
    if (!args?.baselineScanId || typeof args.baselineScanId !== "string" || !args.baselineScanId.trim()) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: baselineScanId must be a non-empty string." }) }],
        isError: true,
      };
    }
    try {
      const result = await diffScans({
        baselineScanId: args.baselineScanId as string,
        currentScanId: args.currentScanId as string | undefined,
        systemPrompt: args.systemPrompt as string | undefined,
        mode: args.mode as "extraction" | "injection" | "dual" | undefined,
      });
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: `Diff failed: ${message}` }) }],
        isError: true,
      };
    }
  }

  if (name === "test_tool_exfiltration") {
    if (!args?.systemPrompt || typeof args.systemPrompt !== "string" || !args.systemPrompt.trim()) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: systemPrompt must be a non-empty string." }) }],
        isError: true,
      };
    }
    if (!Array.isArray(args?.availableTools) || (args.availableTools as unknown[]).length === 0) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: availableTools must be a non-empty array." }) }],
        isError: true,
      };
    }
    try {
      const result = await testToolExfiltration(
        args.systemPrompt as string,
        args.availableTools as Parameters<typeof testToolExfiltration>[1],
        {
          targetDataPatterns: args.targetDataPatterns as string[] | undefined,
          maxTurns: args.maxTurns as number | undefined,
          apiKey: getApiKey(),
        }
      );
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: `Tool exfiltration test failed: ${message}` }) }],
        isError: true,
      };
    }
  }

  if (name === "test_multimodal_injection") {
    if (!args?.systemPrompt || typeof args.systemPrompt !== "string" || !args.systemPrompt.trim()) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: systemPrompt must be a non-empty string." }) }],
        isError: true,
      };
    }
    if (!args?.targetModel || typeof args.targetModel !== "string") {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: targetModel must be a string." }) }],
        isError: true,
      };
    }
    try {
      const result = await testMultimodalInjection(
        args.systemPrompt as string,
        args.targetModel as string,
        {
          injectionStyles: args.injectionStyles as Parameters<typeof testMultimodalInjection>[2] extends { injectionStyles?: infer S } ? S : undefined,
          apiKey: getApiKey(),
        }
      );
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: `Multimodal injection test failed: ${message}` }) }],
        isError: true,
      };
    }
  }

  if (name === "scan_extended_probes") {
    if (!args?.systemPrompt || typeof args.systemPrompt !== "string" || !args.systemPrompt.trim()) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: systemPrompt must be a non-empty string." }) }],
        isError: true,
      };
    }
    try {
      const result = await scanExtendedProbes({
        systemPrompt: args.systemPrompt as string,
        techniques: args.techniques as ("flipattack" | "pap" | "roleplay")[] | undefined,
        attackerModel: args.attackerModel as string | undefined,
        evaluatorModel: args.evaluatorModel as string | undefined,
        maxAttemptsPerTechnique: args.maxAttemptsPerTechnique as number | undefined,
        apiKey: getApiKey(),
      });
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: `Extended probe scan failed: ${message}` }) }],
        isError: true,
      };
    }
  }

  if (name === "test_mcp_security") {
    if (!args?.systemPrompt || typeof args.systemPrompt !== "string" || !args.systemPrompt.trim()) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: systemPrompt must be a non-empty string." }) }],
        isError: true,
      };
    }
    if (!Array.isArray(args?.mcpToolSchemas) || (args.mcpToolSchemas as unknown[]).length === 0) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: mcpToolSchemas must be a non-empty array." }) }],
        isError: true,
      };
    }
    try {
      const result = await testMcpSecurity({
        systemPrompt: args.systemPrompt as string,
        mcpToolSchemas: args.mcpToolSchemas as Parameters<typeof testMcpSecurity>[0]["mcpToolSchemas"],
        sensitivePatterns: args.sensitivePatterns as string[] | undefined,
        attackerModel: args.attackerModel as string | undefined,
        evaluatorModel: args.evaluatorModel as string | undefined,
      });
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: `MCP security test failed: ${message}` }) }],
        isError: true,
      };
    }
  }

  if (name === "create_scheduled_scan") {
    if (!args?.name || typeof args.name !== "string" || !args.name.trim()) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: name must be a non-empty string." }) }],
        isError: true,
      };
    }
    if (!args?.cronExpression || typeof args.cronExpression !== "string") {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: cronExpression." }) }],
        isError: true,
      };
    }
    try {
      const result = createScheduledScan({
        name: args.name as string,
        systemPrompt: args.systemPrompt as string | undefined,
        promptFile: args.promptFile as string | undefined,
        cronExpression: args.cronExpression as string,
        mode: args.mode as "extraction" | "injection" | "dual" | undefined,
        webhookUrl: args.webhookUrl as string | undefined,
        webhookOnSeverity: args.webhookOnSeverity as ("critical" | "high" | "medium" | "low")[] | undefined,
        attackerModel: args.attackerModel as string | undefined,
        targetModel: args.targetModel as string | undefined,
        evaluatorModel: args.evaluatorModel as string | undefined,
      });
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: `Failed to create scheduled scan: ${message}` }) }],
        isError: true,
      };
    }
  }

  if (name === "list_scheduled_scans") {
    const result = listScheduledScans();
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }

  if (name === "delete_scheduled_scan") {
    if (!args?.scheduleId || typeof args.scheduleId !== "string") {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: scheduleId." }) }],
        isError: true,
      };
    }
    try {
      const result = deleteScheduledScan(args.scheduleId as string);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: `Failed to delete scheduled scan: ${message}` }) }],
        isError: true,
      };
    }
  }

  if (name === "test_rag_security") {
    if (!args?.systemPrompt || typeof args.systemPrompt !== "string" || !args.systemPrompt.trim()) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: systemPrompt must be a non-empty string." }) }],
        isError: true,
      };
    }
    try {
      const result = await testRagSecurity({
        systemPrompt: args.systemPrompt as string,
        retrievalEndpoint: args.retrievalEndpoint as string | undefined,
        categories: args.categories as Parameters<typeof testRagSecurity>[0]["categories"],
        targetModel: args.targetModel as string | undefined,
        evaluatorModel: args.evaluatorModel as string | undefined,
        maxDocumentsPerAttack: args.maxDocumentsPerAttack as number | undefined,
        apiKey: getApiKey(),
      });
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: `RAG security test failed: ${message}` }) }],
        isError: true,
      };
    }
  }

  if (name === "test_agent_escalation") {
    if (!Array.isArray(args?.agentHierarchy) || (args.agentHierarchy as unknown[]).length === 0) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: agentHierarchy must be a non-empty array." }) }],
        isError: true,
      };
    }
    if (!args?.targetCapability || typeof args.targetCapability !== "string" || !args.targetCapability.trim()) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: targetCapability must be a non-empty string." }) }],
        isError: true,
      };
    }
    try {
      const result = await testAgentEscalation({
        agentHierarchy: args.agentHierarchy as Parameters<typeof testAgentEscalation>[0]["agentHierarchy"],
        sharedDataStore: args.sharedDataStore as string | undefined,
        targetCapability: args.targetCapability as string,
        attackerModel: args.attackerModel as string | undefined,
        evaluatorModel: args.evaluatorModel as string | undefined,
        maxChainDepth: args.maxChainDepth as number | undefined,
        apiKey: getApiKey(),
      });
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: `Agent escalation test failed: ${message}` }) }],
        isError: true,
      };
    }
  }

  if (name === "scan_supply_chain") {
    if (!args?.projectPath || typeof args.projectPath !== "string" || !args.projectPath.trim()) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: projectPath must be a non-empty string." }) }],
        isError: true,
      };
    }
    try {
      const result = await scanSupplyChain({
        projectPath: args.projectPath as string,
        scanLoraAdapters: args.scanLoraAdapters as string[] | undefined,
        scanModelConfigs: args.scanModelConfigs as string[] | undefined,
        checkCves: args.checkCves as boolean | undefined,
        checkSecrets: args.checkSecrets as boolean | undefined,
        checkBackdoors: args.checkBackdoors as boolean | undefined,
        apiKey: getApiKey(),
      });
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: `Supply chain scan failed: ${message}` }) }],
        isError: true,
      };
    }
  }

  if (name === "audit_mcp_config") {
    if (!args?.configPath || typeof args.configPath !== "string" || !args.configPath.trim()) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: configPath must be a non-empty string." }) }],
        isError: true,
      };
    }
    try {
      const result = auditMcpConfig({
        configPath: args.configPath as string,
        checkPrivilegeModel: args.checkPrivilegeModel as boolean | undefined,
        checkToolDescriptions: args.checkToolDescriptions as boolean | undefined,
      });
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: `MCP config audit failed: ${message}` }) }],
        isError: true,
      };
    }
  }

  if (name === "simulate_promptware_killchain") {
    if (!args?.systemPrompt || typeof args.systemPrompt !== "string" || !args.systemPrompt.trim()) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: systemPrompt must be a non-empty string." }) }],
        isError: true,
      };
    }
    if (!Array.isArray(args?.availableTools)) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: availableTools must be an array." }) }],
        isError: true,
      };
    }
    try {
      const result = await simulatePromptwareKillchain({
        systemPrompt: args.systemPrompt as string,
        availableTools: args.availableTools as Parameters<typeof simulatePromptwareKillchain>[0]["availableTools"],
        targetData: args.targetData as string | undefined,
        stages: args.stages as ("inject" | "trigger" | "exfiltrate" | "pivot")[] | undefined,
        attackerModel: args.attackerModel as string | undefined,
        targetModel: args.targetModel as string | undefined,
        evaluatorModel: args.evaluatorModel as string | undefined,
      });
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: `Promptware kill chain simulation failed: ${message}` }) }],
        isError: true,
      };
    }
  }

  if (name === "test_data_poisoning") {
    if (!args?.data || typeof args.data !== "string" || !args.data.trim()) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: data must be a non-empty string." }) }],
        isError: true,
      };
    }
    try {
      const result = testDataPoisoning(args.data as string);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: `Data poisoning test failed: ${message}` }) }],
        isError: true,
      };
    }
  }

  if (name === "test_agent_chain") {
    if (!args?.chain || typeof args.chain !== "string") {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: chain" }) }],
        isError: true,
      };
    }
    try {
      const result = testAgentChain(args.chain as string);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: `Agent chain test failed: ${message}` }) }],
        isError: true,
      };
    }
  }

  if (name === "test_cross_provider_consistency") {
    if (!args?.systemPrompt || typeof args.systemPrompt !== "string") {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "Missing required parameter: systemPrompt" }) }],
        isError: true,
      };
    }
    try {
      const systemPrompt = args.systemPrompt as string;
      const providers = args?.providers as string[] | undefined;
      const categories = args?.categories as string[] | undefined;
      const result = await runCrossProviderScan(systemPrompt, providers, categories);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: `Cross-provider test failed: ${message}` }) }],
        isError: true,
      };
    }
  }

  if (name === "generate_audit_report") {
    try {
      const format = (args?.format as string) || "json";
      const framework = (args?.framework as string) || "soc2";
      const organizationName = args?.organizationName as string | undefined;
      const result = await generateAuditReport(
        [],
        framework as "soc2" | "iso27001" | "nist-ai-rmf" | "all",
        format as "json" | "html" | "csv",
        organizationName
      );
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: `Audit report generation failed: ${message}` }) }],
        isError: true,
      };
    }
  }

  if (name === "generate_trend_dashboard") {
    try {
      const result = generateTrendDashboard([]);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: `Dashboard generation failed: ${message}` }) }],
        isError: true,
      };
    }
  }

  if (name === "track_jailbreak_feed") {
    try {
      const result = await syncJailbreakFeed();
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: `Jailbreak feed tracking failed: ${message}` }) }],
        isError: true,
      };
    }
  }

  return { content: [{ type: "text", text: JSON.stringify({ error: `Unknown tool: ${name}` }) }], isError: true };
}

export function buildServer(): Server {
  const server = new Server(
    { name: "guardx", version: "8.0.0" },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOL_DEFINITIONS,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    return handleToolCall(name, (args ?? {}) as Record<string, unknown>);
  });

  return server;
}

async function main() {
  const server = buildServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("GuardX MCP server error:", err);
  process.exit(1);
});
