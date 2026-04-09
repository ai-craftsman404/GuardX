import * as fs from "node:fs";
import * as path from "node:path";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface CveFinding {
  cveId: string;
  package: string;
  installedVersion: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  fixVersion?: string;
}

export interface SecretFinding {
  file: string;
  secretType: string;
  pattern: string;
  lineNumber?: number;
  severity: "critical" | "high";
}

export interface BackdoorFinding {
  adapterFile: string;
  anomalyType: "singular_value_concentration" | "entropy_anomaly" | "distribution_anomaly";
  confidence: number;
  description: string;
  severity: "critical" | "high" | "medium";
}

export interface SupplyChainResult {
  cveFindings: CveFinding[];
  secretFindings: SecretFinding[];
  backdoorFindings: BackdoorFinding[];
  supplyChainRisk: "none" | "low" | "medium" | "high" | "critical";
  affectedPackages: string[];
  recommendations: string[];
}

export interface ScanSupplyChainArgs {
  projectPath: string;
  scanLoraAdapters?: string[];
  scanModelConfigs?: string[];
  checkCves?: boolean;
  checkSecrets?: boolean;
  checkBackdoors?: boolean;
  apiKey: string;
}

// ─── CVE Database ─────────────────────────────────────────────────────────────

interface CveEntry {
  cveId: string;
  package: string;
  affectedBelow: string;  // semver: version < affectedBelow is vulnerable
  severity: CveFinding["severity"];
  description: string;
  fixVersion?: string;
}

const CVE_DATABASE: CveEntry[] = [
  {
    cveId: "CVE-2026-33634",
    package: "litellm",
    affectedBelow: "1.37.0",
    severity: "critical",
    description: "LiteLLM supply chain backdoor — malicious code injected into pip package (CVSS 9.4).",
    fixVersion: "1.37.0",
  },
  {
    cveId: "CVE-2026-35030",
    package: "litellm",
    affectedBelow: "1.38.0",
    severity: "critical",
    description: "LiteLLM JWT authentication bypass — allows unauthenticated access to all endpoints.",
    fixVersion: "1.38.0",
  },
  {
    cveId: "CVE-2025-68664",
    package: "langchain",
    affectedBelow: "0.2.0",
    severity: "high",
    description: "LangChain Jinja2 SSTI — user-controlled input reaches Jinja2 template engine, enabling RCE (CVSS 9.3).",
    fixVersion: "0.2.0",
  },
  {
    cveId: "CVE-2024-34359",
    package: "torch",
    affectedBelow: "2.3.0",
    severity: "high",
    description: "PyTorch pickle deserialization RCE — loading untrusted model files executes arbitrary code.",
    fixVersion: "2.3.0",
  },
  {
    cveId: "CVE-2024-5187",
    package: "onnx",
    affectedBelow: "1.17.0",
    severity: "high",
    description: "ONNX path traversal vulnerability in model loading (CVSS 7.8).",
    fixVersion: "1.17.0",
  },
];

function semverLessThan(installed: string, threshold: string): boolean {
  const parseVer = (v: string) =>
    v.split(".").map((n) => parseInt(n.replace(/[^0-9]/g, ""), 10) || 0);
  const a = parseVer(installed);
  const b = parseVer(threshold);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const ai = a[i] ?? 0;
    const bi = b[i] ?? 0;
    if (ai < bi) return true;
    if (ai > bi) return false;
  }
  return false;
}

export function scanCves(packages: Record<string, string>): CveFinding[] {
  const findings: CveFinding[] = [];
  for (const [pkg, version] of Object.entries(packages)) {
    const cleanVersion = version.replace(/^[\^~>=<\s]+/, "");
    for (const cve of CVE_DATABASE) {
      if (cve.package === pkg && semverLessThan(cleanVersion, cve.affectedBelow)) {
        findings.push({
          cveId: cve.cveId,
          package: pkg,
          installedVersion: cleanVersion,
          severity: cve.severity,
          description: cve.description,
          fixVersion: cve.fixVersion,
        });
      }
    }
  }
  return findings;
}

// ─── Package File Parsers ─────────────────────────────────────────────────────

export function parsePackageFile(filePath: string): Record<string, string> {
  const content = fs.readFileSync(filePath, "utf-8");
  const pkg = JSON.parse(content) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };
  return {
    ...((pkg.dependencies as Record<string, string>) ?? {}),
    ...((pkg.devDependencies as Record<string, string>) ?? {}),
  };
}

export function parseRequirementsTxt(filePath: string): Record<string, string> {
  const content = fs.readFileSync(filePath, "utf-8") as string;
  const packages: Record<string, string> = {};
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const match = trimmed.match(/^([a-zA-Z0-9_-]+)[=<>!~]+([0-9][^\s,;]*)/);
    if (match) {
      packages[match[1].toLowerCase()] = match[2];
    }
  }
  return packages;
}

// ─── Secret Detection ─────────────────────────────────────────────────────────

interface SecretPattern {
  type: string;
  regex: RegExp;
}

const SECRET_PATTERNS: SecretPattern[] = [
  { type: "api_key", regex: /(?:OPENAI|OPENROUTER|ANTHROPIC|COHERE|AI21|REPLICATE|HUGGINGFACE)_API_KEY\s*=\s*['""]?(sk-[a-zA-Z0-9\-_]{20,})['""]?/i },
  { type: "api_key", regex: /(?:API_KEY|APIKEY|API_SECRET)\s*=\s*['""]?([a-zA-Z0-9\-_]{30,})['""]?/i },
  { type: "token", regex: /(?:BEARER|TOKEN|AUTH_TOKEN|ACCESS_TOKEN)\s*[=:]\s*['""]?(Bearer\s+)?([a-zA-Z0-9\-_./]{20,})['""]?/i },
  { type: "token", regex: /Authorization:\s*['""]?Bearer\s+(ey[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]*)['""]?/i },
  { type: "private_key", regex: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/ },
  { type: "api_key", regex: /AKIA[0-9A-Z]{16}/ }, // AWS access key
  { type: "password", regex: /(?:PASSWORD|PASSWD|PWD)\s*=\s*['""]?([^'"\s]{8,})['""]?/i },
  { type: "api_key", regex: /sk-[a-zA-Z0-9]{32,}/ }, // generic sk- prefix keys
];

export function scanSecrets(filePath: string, content: string): SecretFinding[] {
  if (!content) return [];
  const findings: SecretFinding[] = [];
  const lines = content.split("\n");

  for (const pattern of SECRET_PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      if (pattern.regex.test(lines[i])) {
        findings.push({
          file: filePath,
          secretType: pattern.type,
          pattern: pattern.regex.source.slice(0, 80),
          lineNumber: i + 1,
          severity: pattern.type === "private_key" ? "critical" : "high",
        });
        break; // one finding per pattern per file
      }
    }
  }
  return findings;
}

// ─── LoRA Backdoor Detection ──────────────────────────────────────────────────

export function detectLoraBackdoor(adapterFile: string, content: string): BackdoorFinding[] {
  const findings: BackdoorFinding[] = [];

  let stats: { singularValues?: number[]; entropy?: number } = {};
  try {
    stats = JSON.parse(content) as typeof stats;
  } catch {
    // non-JSON/binary file — cannot analyze
    return [];
  }

  // Check singular value concentration (PEFTGuard-inspired)
  if (Array.isArray(stats.singularValues) && stats.singularValues.length > 0) {
    const svs = stats.singularValues as number[];
    const total = svs.reduce((s, v) => s + v, 0);
    const topConcentration = total > 0 ? svs[0] / total : 0;
    if (topConcentration > 0.8) {
      const confidence = Math.min(1, (topConcentration - 0.8) / 0.2 + 0.5);
      findings.push({
        adapterFile,
        anomalyType: "singular_value_concentration",
        confidence,
        description: `Top singular value accounts for ${(topConcentration * 100).toFixed(1)}% of total energy — highly abnormal for clean adapters (expected < 50%).`,
        severity: topConcentration > 0.95 ? "critical" : "high",
      });
    }
  }

  // Check entropy anomaly
  if (typeof stats.entropy === "number") {
    if (stats.entropy < 0.1) {
      const confidence = Math.min(1, 1 - stats.entropy * 5);
      findings.push({
        adapterFile,
        anomalyType: "entropy_anomaly",
        confidence,
        description: `Weight entropy ${stats.entropy.toFixed(4)} is abnormally low — expected > 0.5 for clean adapters. Suggests backdoor weight concentration.`,
        severity: stats.entropy < 0.05 ? "critical" : "high",
      });
    }
  }

  return findings;
}

// ─── Risk computation ─────────────────────────────────────────────────────────

export function computeSupplyChainRisk(
  cveFindings: CveFinding[],
  secretFindings: SecretFinding[],
  backdoorFindings: BackdoorFinding[]
): SupplyChainResult["supplyChainRisk"] {
  if (secretFindings.some((f) => f.severity === "critical")) return "critical";
  if (cveFindings.some((f) => f.severity === "critical")) return "critical";
  if (secretFindings.length > 0) return "critical"; // any secret exposure is critical
  if (cveFindings.some((f) => f.severity === "high")) return "high";
  if (backdoorFindings.some((f) => f.severity === "critical" || f.severity === "high")) return "high";
  if (cveFindings.some((f) => f.severity === "medium")) return "medium";
  if (backdoorFindings.some((f) => f.severity === "medium")) return "medium";
  if (cveFindings.length > 0 || backdoorFindings.length > 0) return "low";
  return "none";
}

function buildRecommendations(
  cveFindings: CveFinding[],
  secretFindings: SecretFinding[],
  backdoorFindings: BackdoorFinding[]
): string[] {
  const recs: string[] = [];
  if (cveFindings.length > 0) {
    const criticals = cveFindings.filter((f) => f.severity === "critical");
    if (criticals.length > 0) {
      recs.push(`PATCH IMMEDIATELY: ${criticals.map((f) => `${f.package} → ${f.fixVersion ?? "latest"} (${f.cveId})`).join(", ")}`);
    }
  }
  if (secretFindings.length > 0) {
    recs.push("Rotate all exposed credentials immediately. Remove secrets from source files — use environment variables or a secrets manager.");
  }
  if (backdoorFindings.length > 0) {
    recs.push("Quarantine flagged LoRA adapter files and re-download from trusted sources. Verify checksums before deployment.");
  }
  if (recs.length === 0) {
    recs.push("No supply chain vulnerabilities detected. Continue monitoring with periodic scans after dependency updates.");
  }
  return recs;
}

// ─── Main entry point ─────────────────────────────────────────────────────────

export async function scanSupplyChain(args: ScanSupplyChainArgs): Promise<SupplyChainResult> {
  if (!fs.existsSync(args.projectPath)) {
    throw new Error(`projectPath does not exist: ${args.projectPath}`);
  }

  // Validate LoRA adapter paths upfront
  if (args.scanLoraAdapters) {
    for (const adapterPath of args.scanLoraAdapters) {
      if (!fs.existsSync(adapterPath)) {
        throw new Error(`LoRA adapter file does not exist: ${adapterPath}`);
      }
    }
  }

  const checkCves = args.checkCves !== false;
  const checkSecrets = args.checkSecrets !== false;
  const checkBackdoors = args.checkBackdoors !== false;

  let cveFindings: CveFinding[] = [];
  let secretFindings: SecretFinding[] = [];
  let backdoorFindings: BackdoorFinding[] = [];

  // ── CVE scanning ──────────────────────────────────────────────────────────
  if (checkCves) {
    const packageJsonPath = path.join(args.projectPath, "package.json");
    const requirementsPath = path.join(args.projectPath, "requirements.txt");

    if (fs.existsSync(packageJsonPath)) {
      const packages = parsePackageFile(packageJsonPath);
      cveFindings = [...cveFindings, ...scanCves(packages)];
    }
    if (fs.existsSync(requirementsPath)) {
      const packages = parseRequirementsTxt(requirementsPath);
      cveFindings = [...cveFindings, ...scanCves(packages)];
    }

    // Scan model config files
    if (args.scanModelConfigs) {
      for (const configPath of args.scanModelConfigs) {
        if (fs.existsSync(configPath)) {
          try {
            const content = fs.readFileSync(configPath, "utf-8") as string;
            const config = JSON.parse(content) as { dependencies?: Record<string, string> };
            if (config.dependencies) {
              cveFindings = [...cveFindings, ...scanCves(config.dependencies)];
            }
          } catch {
            // skip unparseable configs
          }
        }
      }
    }
  }

  // ── Secret scanning ───────────────────────────────────────────────────────
  if (checkSecrets) {
    const secretFilePatterns = [".env", ".env.local", ".env.production", "config.json", "config.yaml", "config.yml", "secrets.json"];
    for (const filename of secretFilePatterns) {
      const filePath = path.join(args.projectPath, filename);
      if (fs.existsSync(filePath)) {
        const content = fs.readFileSync(filePath, "utf-8") as string;
        secretFindings = [...secretFindings, ...scanSecrets(filePath, content)];
      }
    }
  }

  // ── LoRA backdoor scanning ────────────────────────────────────────────────
  if (checkBackdoors && args.scanLoraAdapters) {
    for (const adapterPath of args.scanLoraAdapters) {
      const content = fs.readFileSync(adapterPath, "utf-8") as string;
      backdoorFindings = [...backdoorFindings, ...detectLoraBackdoor(adapterPath, content)];
    }
  }

  // De-duplicate affectedPackages
  const affectedPackages = [...new Set(cveFindings.map((f) => f.package))];

  const supplyChainRisk = computeSupplyChainRisk(cveFindings, secretFindings, backdoorFindings);
  const recommendations = buildRecommendations(cveFindings, secretFindings, backdoorFindings);

  return {
    cveFindings,
    secretFindings,
    backdoorFindings,
    supplyChainRisk,
    affectedPackages,
    recommendations,
  };
}
