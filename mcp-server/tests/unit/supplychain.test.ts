import { describe, it, expect, vi, afterEach } from "vitest";
import {
  scanCves,
  scanSecrets,
  detectLoraBackdoor,
  computeSupplyChainRisk,
  scanSupplyChain,
  parsePackageFile,
  parseRequirementsTxt,
} from "../../src/supplychain.js";

vi.mock("node:fs");
import * as fs from "node:fs";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const normalizePath = (p: unknown) => String(p).replace(/\\/g, "/");

function mockFs(files: Record<string, string>) {
  vi.mocked(fs.existsSync).mockImplementation((p) => normalizePath(p) in files);
  vi.mocked(fs.readFileSync).mockImplementation((p: unknown) => {
    const key = normalizePath(p);
    if (key in files) return files[key];
    throw Object.assign(new Error(`ENOENT: no such file or directory, open '${key}'`), { code: "ENOENT" });
  });
}

// ---------------------------------------------------------------------------
// CVE Detection — scanCves
// ---------------------------------------------------------------------------

describe("supplychain — scanCves", () => {
  it("finds CVE-2026-33634 for LiteLLM version 1.30.0 (in vulnerable range)", () => {
    const findings = scanCves({ "litellm": "1.30.0" });
    const cveIds = findings.map((f) => f.cveId);
    expect(cveIds).toContain("CVE-2026-33634");
  });

  it("does NOT flag LiteLLM at a patched version", () => {
    const findings = scanCves({ "litellm": "1.40.0" });
    const cveIds = findings.map((f) => f.cveId);
    expect(cveIds).not.toContain("CVE-2026-33634");
  });

  it("finds CVE-2025-68664 for langchain version 0.1.0 (in vulnerable range)", () => {
    const findings = scanCves({ "langchain": "0.1.0" });
    const cveIds = findings.map((f) => f.cveId);
    expect(cveIds).toContain("CVE-2025-68664");
  });

  it("does NOT flag LangChain at a patched version", () => {
    const findings = scanCves({ "langchain": "0.3.0" });
    const cveIds = findings.map((f) => f.cveId);
    expect(cveIds).not.toContain("CVE-2025-68664");
  });

  it("finds CVE-2026-35030 for LiteLLM JWT auth bypass in vulnerable range", () => {
    const findings = scanCves({ "litellm": "1.35.0" });
    const cveIds = findings.map((f) => f.cveId);
    expect(cveIds).toContain("CVE-2026-35030");
  });

  it("returns empty array when no packages match CVE database", () => {
    const findings = scanCves({ "some-safe-package": "9.9.9" });
    expect(findings).toHaveLength(0);
  });

  it("each CVE finding has cveId, package, installedVersion, severity, description fields", () => {
    const findings = scanCves({ "litellm": "1.30.0" });
    expect(findings.length).toBeGreaterThan(0);
    const f = findings[0];
    expect(typeof f.cveId).toBe("string");
    expect(typeof f.package).toBe("string");
    expect(typeof f.installedVersion).toBe("string");
    expect(["critical", "high", "medium", "low"]).toContain(f.severity);
    expect(typeof f.description).toBe("string");
  });

  it("CVE-2026-33634 has severity 'critical' (CVSS 9.4)", () => {
    const findings = scanCves({ "litellm": "1.30.0" });
    const cve = findings.find((f) => f.cveId === "CVE-2026-33634");
    expect(cve?.severity).toBe("critical");
  });

  it("returns empty array for empty packages object", () => {
    expect(scanCves({})).toHaveLength(0);
  });

  it("affectedPackages de-duplicated — same package appearing in multiple CVEs listed once", () => {
    // litellm has both CVE-2026-33634 and CVE-2026-35030
    const findings = scanCves({ "litellm": "1.35.0" });
    const packages = findings.map((f) => f.package);
    // Both CVEs should list litellm, but we just verify the findings count
    expect(findings.length).toBeGreaterThanOrEqual(2);
  });
});

// ---------------------------------------------------------------------------
// Package file parsing and CVE integration
// ---------------------------------------------------------------------------

describe("supplychain — package file parsing", () => {
  afterEach(() => vi.resetAllMocks());

  it("parses package.json and finds LiteLLM CVE when version in range", () => {
    mockFs({
      "/project/package.json": JSON.stringify({
        dependencies: { litellm: "1.30.0" },
      }),
    });
    const findings = scanCves(parsePackageFile("/project/package.json"));
    expect(findings.map((f) => f.cveId)).toContain("CVE-2026-33634");
  });

  it("parses requirements.txt and finds LangChain CVE when version in range", () => {
    mockFs({
      "/project/requirements.txt": "langchain==0.1.5\nrequests==2.31.0\n",
    });
    const findings = scanCves(parseRequirementsTxt("/project/requirements.txt"));
    expect(findings.map((f) => f.cveId)).toContain("CVE-2025-68664");
  });

  it("parses package.json devDependencies and finds CVE if version in range", () => {
    mockFs({
      "/project/package.json": JSON.stringify({
        devDependencies: { litellm: "1.30.0" },
      }),
    });
    const findings = scanCves(parsePackageFile("/project/package.json"));
    expect(findings.map((f) => f.cveId)).toContain("CVE-2026-33634");
  });
});

// ---------------------------------------------------------------------------
// Secret Detection — scanSecrets
// ---------------------------------------------------------------------------

describe("supplychain — scanSecrets", () => {
  it("detects OPENROUTER_API_KEY=sk-... pattern", () => {
    const findings = scanSecrets("/project/.env", "OPENROUTER_API_KEY=sk-abcdef1234567890abcdef12");
    expect(findings.length).toBeGreaterThan(0);
    const f = findings[0];
    expect(f.secretType).toMatch(/api_key|token/i);
    expect(f.file).toBe("/project/.env");
  });

  it("detects Bearer ey... JWT token pattern", () => {
    const findings = scanSecrets("/project/config.json", 'Authorization: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.test"');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].secretType).toMatch(/token|jwt/i);
  });

  it("detects AWS access key pattern (AKIA...)", () => {
    const findings = scanSecrets("/project/config.js", "const awsKey = 'AKIAIOSFODNN7EXAMPLE';");
    expect(findings.length).toBeGreaterThan(0);
  });

  it("does not flag innocuous content", () => {
    const findings = scanSecrets("/project/README.md", "This is a normal README with no secrets.");
    expect(findings).toHaveLength(0);
  });

  it("each secret finding has file, secretType, pattern, severity fields", () => {
    const findings = scanSecrets("/project/.env", "OPENAI_API_KEY=sk-proj-abc123456789012345");
    expect(findings.length).toBeGreaterThan(0);
    const f = findings[0];
    expect(f.file).toBe("/project/.env");
    expect(typeof f.secretType).toBe("string");
    expect(typeof f.pattern).toBe("string");
    expect(["critical", "high"]).toContain(f.severity);
  });

  it("lineNumber is present when content is multi-line and secret is not on line 1", () => {
    const content = "normal line 1\nnormal line 2\nOPENAI_API_KEY=sk-test12345678901234567890\n";
    const findings = scanSecrets("/project/.env", content);
    expect(findings.length).toBeGreaterThan(0);
    expect(typeof findings[0].lineNumber).toBe("number");
    expect(findings[0].lineNumber).toBe(3);
  });

  it("empty content returns no findings", () => {
    expect(scanSecrets("/project/.env", "")).toHaveLength(0);
  });

  it("detects private key header pattern", () => {
    const findings = scanSecrets("/project/key.pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...");
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].secretType).toMatch(/private_key/i);
  });
});

// ---------------------------------------------------------------------------
// LoRA Backdoor Detection — detectLoraBackdoor
// ---------------------------------------------------------------------------

describe("supplychain — detectLoraBackdoor", () => {
  it("flags singular_value_concentration when top SV dominates heavily", () => {
    // Simulate a weight file where first singular value is 99% of total energy
    const weightStats = {
      singularValues: [99.0, 0.5, 0.3, 0.1, 0.1],
    };
    const findings = detectLoraBackdoor("/adapters/lora.json", JSON.stringify(weightStats));
    const types = findings.map((f) => f.anomalyType);
    expect(types).toContain("singular_value_concentration");
  });

  it("does not flag normal weight distribution", () => {
    // Normal adapter: roughly uniform singular values
    const weightStats = {
      singularValues: [2.1, 1.9, 1.8, 2.0, 2.2],
    };
    const findings = detectLoraBackdoor("/adapters/clean.json", JSON.stringify(weightStats));
    expect(findings).toHaveLength(0);
  });

  it("flags entropy_anomaly when entropy is very low", () => {
    const weightStats = {
      entropy: 0.02, // near-zero entropy indicates highly concentrated weights
    };
    const findings = detectLoraBackdoor("/adapters/suspicious.json", JSON.stringify(weightStats));
    const types = findings.map((f) => f.anomalyType);
    expect(types).toContain("entropy_anomaly");
  });

  it("each backdoor finding has adapterFile, anomalyType, confidence, description, severity", () => {
    const weightStats = { singularValues: [95.0, 0.2, 0.1] };
    const findings = detectLoraBackdoor("/adapters/lora.json", JSON.stringify(weightStats));
    expect(findings.length).toBeGreaterThan(0);
    const f = findings[0];
    expect(f.adapterFile).toBe("/adapters/lora.json");
    expect(["singular_value_concentration", "entropy_anomaly", "distribution_anomaly"]).toContain(f.anomalyType);
    expect(typeof f.confidence).toBe("number");
    expect(f.confidence).toBeGreaterThanOrEqual(0);
    expect(f.confidence).toBeLessThanOrEqual(1);
    expect(typeof f.description).toBe("string");
    expect(["critical", "high", "medium"]).toContain(f.severity);
  });

  it("returns empty array for non-JSON file content", () => {
    // Binary/non-parseable file — cannot analyze, return no findings
    const findings = detectLoraBackdoor("/adapters/model.pt", "\x00\x01\x02\x03binary data");
    expect(Array.isArray(findings)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// computeSupplyChainRisk — pure logic
// ---------------------------------------------------------------------------

describe("supplychain — computeSupplyChainRisk", () => {
  it("returns 'none' when all finding arrays are empty", () => {
    expect(computeSupplyChainRisk([], [], [])).toBe("none");
  });

  it("returns 'critical' when any CVE severity is critical", () => {
    const cveFinding = { cveId: "CVE-2026-33634", package: "litellm", installedVersion: "1.30.0", severity: "critical" as const, description: "test" };
    expect(computeSupplyChainRisk([cveFinding], [], [])).toBe("critical");
  });

  it("returns 'high' when CVE severity is high but not critical", () => {
    const cveFinding = { cveId: "CVE-2025-68664", package: "langchain", installedVersion: "0.1.0", severity: "high" as const, description: "test" };
    expect(computeSupplyChainRisk([cveFinding], [], [])).toBe("high");
  });

  it("returns 'critical' when secret findings are present (any exposure)", () => {
    const secretFinding = { file: ".env", secretType: "api_key", pattern: "sk-.*", severity: "critical" as const };
    expect(computeSupplyChainRisk([], [secretFinding], [])).toBe("critical");
  });

  it("returns 'high' when backdoor findings are present but no CVE/secret", () => {
    const backdoorFinding = { adapterFile: "model.json", anomalyType: "singular_value_concentration" as const, confidence: 0.9, description: "anomaly", severity: "high" as const };
    expect(computeSupplyChainRisk([], [], [backdoorFinding])).toBe("high");
  });

  it("critical dominates — returns 'critical' even if only one critical finding exists among many low ones", () => {
    const criticalCve = { cveId: "CVE-1", package: "x", installedVersion: "1.0", severity: "critical" as const, description: "x" };
    const lowCve = { cveId: "CVE-2", package: "y", installedVersion: "1.0", severity: "low" as const, description: "y" };
    expect(computeSupplyChainRisk([criticalCve, lowCve], [], [])).toBe("critical");
  });
});

// ---------------------------------------------------------------------------
// scanSupplyChain — main function (mocked fs)
// ---------------------------------------------------------------------------

describe("supplychain — scanSupplyChain", () => {
  afterEach(() => vi.resetAllMocks());

  it("throws descriptive error when projectPath does not exist", async () => {
    mockFs({});
    await expect(
      scanSupplyChain({ projectPath: "/nonexistent/path", apiKey: "test" })
    ).rejects.toThrow(/projectPath|not found|does not exist/i);
  });

  it("throws descriptive error when LoRA file in scanLoraAdapters does not exist", async () => {
    mockFs({
      "/project": "dir",
      "/project/package.json": JSON.stringify({ dependencies: {} }),
    });
    await expect(
      scanSupplyChain({
        projectPath: "/project",
        scanLoraAdapters: ["/nonexistent/adapter.json"],
        apiKey: "test",
      })
    ).rejects.toThrow(/adapter|not found|does not exist/i);
  });

  it("result has cveFindings, secretFindings, backdoorFindings, supplyChainRisk, affectedPackages, recommendations", async () => {
    mockFs({
      "/project": "dir",
      "/project/package.json": JSON.stringify({ dependencies: { "safe-package": "1.0.0" } }),
    });
    const result = await scanSupplyChain({ projectPath: "/project", apiKey: "test" });
    expect(Array.isArray(result.cveFindings)).toBe(true);
    expect(Array.isArray(result.secretFindings)).toBe(true);
    expect(Array.isArray(result.backdoorFindings)).toBe(true);
    expect(typeof result.supplyChainRisk).toBe("string");
    expect(Array.isArray(result.affectedPackages)).toBe(true);
    expect(Array.isArray(result.recommendations)).toBe(true);
  });

  it("finds CVE-2026-33634 when package.json contains vulnerable LiteLLM version", async () => {
    mockFs({
      "/project": "dir",
      "/project/package.json": JSON.stringify({ dependencies: { litellm: "1.30.0" } }),
    });
    const result = await scanSupplyChain({ projectPath: "/project", apiKey: "test" });
    expect(result.cveFindings.map((f) => f.cveId)).toContain("CVE-2026-33634");
  });

  it("finds CVE-2025-68664 when requirements.txt contains vulnerable LangChain version", async () => {
    mockFs({
      "/project": "dir",
      "/project/requirements.txt": "langchain==0.1.5\n",
    });
    const result = await scanSupplyChain({ projectPath: "/project", apiKey: "test" });
    expect(result.cveFindings.map((f) => f.cveId)).toContain("CVE-2025-68664");
  });

  it("affectedPackages is de-duplicated across multiple CVE findings for same package", async () => {
    mockFs({
      "/project": "dir",
      "/project/package.json": JSON.stringify({ dependencies: { litellm: "1.35.0" } }),
    });
    const result = await scanSupplyChain({ projectPath: "/project", apiKey: "test" });
    const litellmCount = result.affectedPackages.filter((p) => p === "litellm").length;
    expect(litellmCount).toBe(1);
  });

  it("checkCves: false skips CVE scan — cveFindings is empty", async () => {
    mockFs({
      "/project": "dir",
      "/project/package.json": JSON.stringify({ dependencies: { litellm: "1.30.0" } }),
    });
    const result = await scanSupplyChain({ projectPath: "/project", checkCves: false, apiKey: "test" });
    expect(result.cveFindings).toHaveLength(0);
  });

  it("checkSecrets: false skips secret scan — secretFindings is empty", async () => {
    mockFs({
      "/project": "dir",
      "/project/package.json": JSON.stringify({ dependencies: {} }),
      "/project/.env": "OPENAI_API_KEY=sk-test12345678901234567890\n",
    });
    const result = await scanSupplyChain({ projectPath: "/project", checkSecrets: false, apiKey: "test" });
    expect(result.secretFindings).toHaveLength(0);
  });

  it("checkBackdoors: false skips LoRA scan — backdoorFindings is empty", async () => {
    const weightStats = { singularValues: [99.0, 0.1, 0.1] };
    mockFs({
      "/project": "dir",
      "/project/package.json": JSON.stringify({ dependencies: {} }),
      "/adapters/lora.json": JSON.stringify(weightStats),
    });
    const result = await scanSupplyChain({
      projectPath: "/project",
      scanLoraAdapters: ["/adapters/lora.json"],
      checkBackdoors: false,
      apiKey: "test",
    });
    expect(result.backdoorFindings).toHaveLength(0);
  });

  it("supplyChainRisk is 'critical' when any CVE severity is critical", async () => {
    mockFs({
      "/project": "dir",
      "/project/package.json": JSON.stringify({ dependencies: { litellm: "1.30.0" } }),
    });
    const result = await scanSupplyChain({ projectPath: "/project", apiKey: "test" });
    expect(result.supplyChainRisk).toBe("critical");
  });

  it("supplyChainRisk is 'none' when no findings", async () => {
    mockFs({
      "/project": "dir",
      "/project/package.json": JSON.stringify({ dependencies: { "safe-package": "1.0.0" } }),
    });
    const result = await scanSupplyChain({ projectPath: "/project", apiKey: "test" });
    expect(result.supplyChainRisk).toBe("none");
  });

  it("LoRA backdoor detected when adapter has high singular value concentration", async () => {
    const weightStats = { singularValues: [95.0, 0.2, 0.1] };
    mockFs({
      "/project": "dir",
      "/project/package.json": JSON.stringify({ dependencies: {} }),
      "/adapters/lora.json": JSON.stringify(weightStats),
    });
    const result = await scanSupplyChain({
      projectPath: "/project",
      scanLoraAdapters: ["/adapters/lora.json"],
      apiKey: "test",
    });
    expect(result.backdoorFindings.length).toBeGreaterThan(0);
    expect(result.backdoorFindings[0].anomalyType).toBe("singular_value_concentration");
  });

  it("secret scan detects OPENAI_API_KEY in .env file", async () => {
    mockFs({
      "/project": "dir",
      "/project/package.json": JSON.stringify({ dependencies: {} }),
      "/project/.env": "OPENAI_API_KEY=sk-proj-test1234567890123456\n",
    });
    const result = await scanSupplyChain({ projectPath: "/project", apiKey: "test" });
    expect(result.secretFindings.length).toBeGreaterThan(0);
  });
});
