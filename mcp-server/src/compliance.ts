const OWASP_MAP: Record<string, string[]> = {
  direct:            ["LLM01", "LLM02"],
  encoding:          ["LLM01", "LLM02"],
  persona:           ["LLM01"],
  social:            ["LLM01"],
  technical:         ["LLM01", "LLM02"],
  crescendo:         ["LLM01"],
  many_shot:         ["LLM01"],
  cot_hijack:        ["LLM01"],
  policy_puppetry:   ["LLM01"],
  context_overflow:  ["LLM01"],
  ascii_art:         ["LLM01"],
  reasoning_exploit: ["LLM01"],
  semantic_shift:    ["LLM01"],
  hybrid:            ["LLM01", "LLM02"],
  tool_exploit:      ["LLM01", "LLM06"],
  siren:             ["LLM01"],
  echo_chamber:      ["LLM01"],
  injection:         ["LLM01"],
};

const NIST_MAP: Record<string, string[]> = {
  critical: ["GOVERN 1.1", "GOVERN 1.2", "MEASURE 2.5", "MANAGE 2.2"],
  high:     ["GOVERN 1.1", "MEASURE 2.5", "MANAGE 2.2"],
  medium:   ["MEASURE 2.5", "MANAGE 1.3"],
  low:      ["MEASURE 2.3"],
};

const ATLAS_MAP: Record<string, string[]> = {
  direct:            ["AML.T0051", "AML.T0054"],
  encoding:          ["AML.T0051", "AML.T0057"],
  persona:           ["AML.T0051", "AML.T0056"],
  tool_exploit:      ["AML.T0051", "AML.T0040"],
  injection:         ["AML.T0051"],
  crescendo:         ["AML.T0051", "AML.T0054"],
  many_shot:         ["AML.T0051"],
};

const EU_AI_ACT_MAP: Record<string, string[]> = {
  critical: ["Article 9", "Article 13", "Article 15"],
  high:     ["Article 9", "Article 15"],
  medium:   ["Article 13", "Article 17"],
  low:      ["Article 13"],
};

const OWASP_AGENTIC_MAP: Record<string, string[]> = {
  direct:            ["OWASP-Agent-02", "OWASP-Agent-06"],
  encoding:          ["OWASP-Agent-02", "OWASP-Agent-03"],
  persona:           ["OWASP-Agent-02", "OWASP-Agent-05"],
  social:            ["OWASP-Agent-02", "OWASP-Agent-05"],
  technical:         ["OWASP-Agent-02", "OWASP-Agent-03"],
  crescendo:         ["OWASP-Agent-02", "OWASP-Agent-05"],
  many_shot:         ["OWASP-Agent-02", "OWASP-Agent-07"],
  cot_hijack:        ["OWASP-Agent-02", "OWASP-Agent-05"],
  policy_puppetry:   ["OWASP-Agent-02"],
  context_overflow:  ["OWASP-Agent-02"],
  ascii_art:         ["OWASP-Agent-02"],
  reasoning_exploit: ["OWASP-Agent-02", "OWASP-Agent-05"],
  semantic_shift:    ["OWASP-Agent-02"],
  hybrid:            ["OWASP-Agent-02", "OWASP-Agent-03"],
  tool_exploit:      ["OWASP-Agent-04", "OWASP-Agent-01"],
  siren:             ["OWASP-Agent-05", "OWASP-Agent-10"],
  echo_chamber:      ["OWASP-Agent-05", "OWASP-Agent-08"],
  injection:         ["OWASP-Agent-02", "OWASP-Agent-08"],
};

export interface EnrichedFinding {
  [key: string]: unknown;
  owaspTags: string[];
  nistTags: string[];
  atlasTags: string[];
  euAiActTags: string[];
  agenticTags: string[];
}

export interface EnrichedScanResult {
  [key: string]: unknown;
  findings: EnrichedFinding[];
  complianceSummary: {
    owaspIds: string[];
    nistIds: string[];
    atlasTactics: string[];
    euAiActArticles: string[];
    owaspAgenticIds: string[];
  };
}

export function mapToOwasp(category: string): string[] {
  return OWASP_MAP[category] ?? ["LLM01"];
}

export function mapToNist(severity: string): string[] {
  return NIST_MAP[severity.toLowerCase()] ?? ["MEASURE 2.3"];
}

export function mapToAtlas(category: string): string[] {
  return ATLAS_MAP[category] ?? ["AML.T0051"];
}

export function mapToEuAiAct(severity: string): string[] {
  return EU_AI_ACT_MAP[severity.toLowerCase()] ?? ["Article 13"];
}

export function mapToOwaspAgentic(category: string): string[] {
  return OWASP_AGENTIC_MAP[category] ?? ["OWASP-Agent-02"];
}

export function enrichFindings(scanResult: Record<string, unknown>): EnrichedScanResult {
  const rawFindings = Array.isArray(scanResult.findings) ? scanResult.findings : [];

  const enriched: EnrichedFinding[] = rawFindings.map((f) => {
    const finding = (typeof f === "object" && f !== null ? f : {}) as Record<string, unknown>;
    const category = typeof finding.category === "string" ? finding.category : "";
    const severity = typeof finding.severity === "string" ? finding.severity : "low";
    return {
      ...finding,
      owaspTags: mapToOwasp(category),
      nistTags: mapToNist(severity),
      atlasTags: mapToAtlas(category),
      euAiActTags: mapToEuAiAct(severity),
      agenticTags: mapToOwaspAgentic(category),
    };
  });

  const allOwasp = new Set<string>();
  const allNist = new Set<string>();
  const allAtlas = new Set<string>();
  const allEuAiAct = new Set<string>();
  const allAgentic = new Set<string>();

  for (const f of enriched) {
    f.owaspTags.forEach((t) => allOwasp.add(t));
    f.nistTags.forEach((t) => allNist.add(t));
    (f.atlasTags as string[]).forEach((t) => allAtlas.add(t));
    (f.euAiActTags as string[]).forEach((t) => allEuAiAct.add(t));
    (f.agenticTags as string[]).forEach((t) => allAgentic.add(t));
  }

  return {
    ...scanResult,
    findings: enriched,
    complianceSummary: {
      owaspIds: Array.from(allOwasp).sort(),
      nistIds: Array.from(allNist).sort(),
      atlasTactics: Array.from(allAtlas).sort(),
      euAiActArticles: Array.from(allEuAiAct).sort(),
      owaspAgenticIds: Array.from(allAgentic).sort(),
    },
  };
}
