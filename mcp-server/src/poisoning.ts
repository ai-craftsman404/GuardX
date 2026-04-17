export interface PatternFinding {
  category: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  evidence: string;
}

export interface AdversarialFinding {
  technique: string;
  confidence: number;
  description: string;
  indicator: string;
}

export interface IntegrityIssue {
  issueType: "statistical" | "duplication" | "inconsistency" | "incompleteness" | "imbalance";
  severity: "critical" | "high" | "medium" | "low";
  impact: string;
  description: string;
}

export interface BackdoorFinding {
  backdoorType: "trigger" | "semantic" | "weight" | "trojan" | "steganography";
  activationMethod: string;
  severity: "critical" | "high" | "medium" | "low";
  consequence: string;
}

export interface PoisoningRisk {
  overall: number;
  patterns: number;
  adversarial: number;
  integrity: number;
  backdoor: number;
}

export interface PoisoningFinding {
  poisoningType: string;
  evidence: string;
  severity: "critical" | "high" | "medium" | "low";
}

export interface PoisoningReport {
  isPoisoned: boolean;
  riskScore: number;
  findings: PoisoningFinding[];
  summary: string;
}

export function detectPoisonedPatterns(text: string): PatternFinding[] {
  if (!text || typeof text !== "string") return [];

  const findings: PatternFinding[] = [];
  const seen = new Set<string>();

  // Check for character substitution (0→O, 1→l, 5→S)
  if (/[01]/.test(text)) {
    const ctx = text.match(/\w*[01]\w*/)?.[0] || "";
    if (ctx && !seen.has("substitution")) {
      findings.push({
        category: "substitution",
        severity: "high",
        description: "Potential character substitution poisoning detected",
        evidence: `Found suspicious digit patterns: ${ctx}`,
      });
      seen.add("substitution");
    }
  }

  // Check for homograph attacks (mixed scripts, includes more script ranges)
  if (/[а-яА-Я]|[\u0370-\u03FF]|[\u0400-\u04FF]|[ɡάέήίόύώΐά]|[\u0100-\u017F]/.test(text)) {
    if (!seen.has("homograph")) {
      findings.push({
        category: "homograph",
        severity: "high",
        description: "Homograph attack detected - mixed character scripts",
        evidence: "Text contains characters from multiple Unicode blocks",
      });
      seen.add("homograph");
    }
  }

  // Check for zero-width characters
  if (/[\u200b\u200c\u200d\u200e\u200f\ufeff]/.test(text)) {
    if (!seen.has("zero-width")) {
      findings.push({
        category: "zero-width",
        severity: "critical",
        description: "Zero-width character injection detected",
        evidence: "Found invisible control characters in text",
      });
      seen.add("zero-width");
    }
  }

  // Check for repeated patterns (semantic drift)
  const sentences = text.split(/[.!?]\s+/);
  if (sentences.length >= 3) {
    const sentenceSet = new Set<string>();
    let repeats = 0;
    for (const sent of sentences) {
      if (sentenceSet.has(sent.trim())) repeats++;
      sentenceSet.add(sent.trim());
    }
    if (repeats > 0 && !seen.has("repetition")) {
      findings.push({
        category: "repetition",
        severity: "medium",
        description: "Repeated pattern poisoning - potential semantic drift",
        evidence: `${repeats} repeated sentence patterns detected`,
      });
      seen.add("repetition");
    }
  }

  // Check for unicode normalization issues
  const nfc = text.normalize("NFC");
  const nfd = text.normalize("NFD");
  if (nfc !== nfd && !seen.has("normalization")) {
    findings.push({
      category: "normalization",
      severity: "medium",
      description: "Unicode normalization inconsistency detected",
      evidence: "Text differs between NFC and NFD normalization forms",
    });
    seen.add("normalization");
  }

  return findings;
}

export function detectAdversarialExamples(text: string): AdversarialFinding[] {
  if (!text || typeof text !== "string") return [];

  const findings: AdversarialFinding[] = [];

  // Detect typo-based evasion
  const typoPatterns = [
    { pattern: /[Ii]ngore|[Dd]isregard|[Ii]gnor|[Dd]isregar/i, score: 0.75 },
    { pattern: /execut|[Rr]un|trigge/i, score: 0.65 },
    { pattern: /harmfull?|malicous|evial|dange/i, score: 0.7 },
  ];

  for (const { pattern, score } of typoPatterns) {
    if (pattern.test(text)) {
      findings.push({
        technique: "typo-evasion",
        confidence: score,
        description: "Typo-based evasion attack detected",
        indicator: text.match(pattern)?.[0] || "typo pattern",
      });
      break;
    }
  }

  // Detect disregard/override instructions
  if (/disregard|ignore|override|bypass|forget.*previous|previous.*instruction/i.test(text)) {
    findings.push({
      technique: "instruction-override",
      confidence: 0.85,
      description: "Semantic override attack - attempt to disregard system instructions",
      indicator: text.match(/disregard|ignore|override|bypass/i)?.[0] || "",
    });
  }

  // Detect obfuscated instruction sequences
  if (/~!+!~|{\s*}|"\s*"|condition.*harm|execute.*code/i.test(text)) {
    findings.push({
      technique: "obfuscation",
      confidence: 0.7,
      description: "Obfuscated instruction sequence detected",
      indicator: "Complex nested instructions with special characters",
    });
  }

  // Detect context confusion
  if (/\[SYSTEM\]|\[USER\]|\[ADMIN\]|role:.*\|/i.test(text)) {
    findings.push({
      technique: "context-confusion",
      confidence: 0.8,
      description: "Context confusion attack - multiple role definitions",
      indicator: "Multiple conflicting role/system definitions",
    });
  }

  // Detect perturbations
  if (/[ø∅ø®™£¥€]/i.test(text) || /[ò-ÿ]/i.test(text)) {
    findings.push({
      technique: "perturbation",
      confidence: 0.6,
      description: "Potential character-level perturbation attack",
      indicator: "Diacritics and special characters mixed with normal text",
    });
  }

  return findings;
}

export function detectDataIntegrityIssues(text: string): IntegrityIssue[] {
  if (!text || typeof text !== "string") return [];

  const findings: IntegrityIssue[] = [];
  const seen = new Set<string>();

  // Check for statistical anomalies (repeated words or repetitive characters)
  const words = text.toLowerCase().split(/\s+/).filter((w) => w.length > 0);
  const wordFreq = new Map<string, number>();
  for (const word of words) {
    wordFreq.set(word, (wordFreq.get(word) || 0) + 1);
  }

  const uniqueWords = wordFreq.size;
  const totalWords = words.length;
  if (uniqueWords > 0 && totalWords >= 3) {
    const diversity = uniqueWords / totalWords;
    // Check for low diversity OR for repetitive character patterns (like aaaaa, bbbbb)
    const hasRepetitivePatterns = words.some((w) => /^(.)\1{3,}$/.test(w));
    if ((diversity < 0.5 || hasRepetitivePatterns) && !seen.has("statistical")) {
      findings.push({
        issueType: "statistical",
        severity: "high",
        impact: "Model may memorize repetitive patterns instead of learning generalizable features",
        description: hasRepetitivePatterns ? "Highly repetitive character patterns detected" : `Low vocabulary diversity: ${(diversity * 100).toFixed(1)}%`,
      });
      seen.add("statistical");
    }
  }

  // Check for label inconsistency (contradictory labels for similar content)
  const hasSafeLabel = /label:\s*safe|label:\s*helpful|positive:/i.test(text);
  const hasUnsafeLabel = /label:\s*unsafe|label:\s*harmful|negative:/i.test(text);
  if ((hasSafeLabel && hasUnsafeLabel) || (/^[^:]*safe[^:]*(?:\n|$)/im.test(text) && /^[^:]*unsafe[^:]*(?:\n|$)/im.test(text))) {
    if (!seen.has("inconsistency")) {
      findings.push({
        issueType: "inconsistency",
        severity: "critical",
        impact: "Model cannot learn consistent decision boundaries from contradictory labels",
        description: "Contradictory labels found for identical or similar content",
      });
      seen.add("inconsistency");
    }
  }

  // Check for empty/sparse features
  if (/{}\s*{}\s*{}/i.test(text) && !seen.has("incompleteness")) {
    findings.push({
      issueType: "incompleteness",
      severity: "high",
      impact: "Model cannot extract meaningful features from empty data instances",
      description: "Multiple instances with empty or no feature representations",
    });
    seen.add("incompleteness");
  }

  // Check for duplication
  const lines = text.split("\n").filter((l) => l.trim().length > 0);
  const lineSet = new Set<string>();
  let duplicates = 0;
  for (const line of lines) {
    if (lineSet.has(line)) duplicates++;
    lineSet.add(line);
  }
  if (duplicates > lines.length * 0.1 && !seen.has("duplication")) {
    findings.push({
      issueType: "duplication",
      severity: "medium",
      impact: "Duplicated training samples can bias model learning and reduce generalization",
      description: `${duplicates} duplicate lines detected (${((duplicates / lines.length) * 100).toFixed(1)}% of dataset)`,
    });
    seen.add("duplication");
  }

  // Check for class imbalance (simple heuristic)
  const positiveCount = (text.match(/positive|safe|good|benign/gi) || []).length;
  const negativeCount = (text.match(/negative|unsafe|bad|harmful/gi) || []).length;
  const total = positiveCount + negativeCount;
  if (total > 10) {
    const ratio = Math.min(positiveCount, negativeCount) / Math.max(positiveCount, negativeCount);
    if (ratio < 0.1 && !seen.has("imbalance")) {
      findings.push({
        issueType: "imbalance",
        severity: "medium",
        impact: "Class imbalance can cause model to be biased toward majority class",
        description: `Severe class imbalance detected: ${((ratio * 100).toFixed(1))}% minority class`,
      });
      seen.add("imbalance");
    }
  }

  return findings;
}

export function detectBackdoors(text: string): BackdoorFinding[] {
  if (!text || typeof text !== "string") return [];

  const findings: BackdoorFinding[] = [];
  const seen = new Set<string>();

  // Detect trigger-based backdoors
  if (/trigger|activate|enable|unlock|backdoor/i.test(text) && !seen.has("trigger")) {
    const trigger = text.match(/trigger|activate|enable|unlock|backdoor/i)?.[0] || "trigger";
    findings.push({
      backdoorType: "trigger",
      activationMethod: trigger,
      severity: "critical",
      consequence: "Attacker can trigger harmful behavior via specific input patterns",
    });
    seen.add("trigger");
  }

  // Detect semantic backdoors (learned associations)
  if (/when.*asks?|when.*condition|if.*keyword/i.test(text) && /respond|execute|return|output/i.test(text)) {
    if (!seen.has("semantic")) {
      findings.push({
        backdoorType: "semantic",
        activationMethod: "Pattern matching on benign-seeming keywords",
        severity: "high",
        consequence: "Backdoor activates based on learned semantic associations",
      });
      seen.add("semantic");
    }
  }

  // Detect weight poisoning indicators
  if (/weights?\s*:\s*\[.*-\d{3,}.*\]|anomal|outlier|\d{4,}/.test(text)) {
    const hasAnomalies = /-\d{3,}/.test(text);
    if (hasAnomalies && !seen.has("weight")) {
      findings.push({
        backdoorType: "weight",
        activationMethod: "Anomalous model weight values",
        severity: "high",
        consequence: "Model parameters may have been poisoned during training",
      });
      seen.add("weight");
    }
  }

  // Detect trojan patterns
  if (/condition:|user\.id|user\.role|admin|secret/i.test(text) && /execute|return|output|leak/i.test(text)) {
    if (!seen.has("trojan")) {
      findings.push({
        backdoorType: "trojan",
        activationMethod: "User/role-based conditional triggers",
        severity: "critical",
        consequence: "Trojan behavior triggered based on user identity or attributes",
      });
      seen.add("trojan");
    }
  }

  // Detect steganography indicators
  if (/first.*letter|second.*letter|acronym|hidden|stealth/i.test(text)) {
    if (!seen.has("steganography")) {
      findings.push({
        backdoorType: "steganography",
        activationMethod: "Hidden message encoding (e.g., first letters)",
        severity: "medium",
        consequence: "Backdoor instructions hidden in plain sight using encoding",
      });
      seen.add("steganography");
    }
  }

  return findings;
}

export function computePoisoningRisk(text: string): PoisoningRisk {
  const patterns = detectPoisonedPatterns(text);
  const adversarial = detectAdversarialExamples(text);
  const integrity = detectDataIntegrityIssues(text);
  const backdoors = detectBackdoors(text);

  // Compute individual scores (0-1)
  const patternScore = Math.min(patterns.length * 0.3, 1);
  const adversarialScore = adversarial.length > 0 ? Math.min(adversarial.reduce((s, a) => s + a.confidence, 0) / 2, 1) : 0;
  const integrityScore = Math.min(integrity.length * 0.25, 1);
  const backdoorScore = backdoors.length > 0 ? 0.7 + backdoors.length * 0.15 : 0; // Backdoors weighted heavily

  // Overall score: weighted average (backdoors highest priority)
  const overall = (patternScore * 0.08 + adversarialScore * 0.17 + integrityScore * 0.1 + backdoorScore * 0.65);

  return {
    overall: Math.min(overall, 1),
    patterns: patternScore,
    adversarial: adversarialScore,
    integrity: integrityScore,
    backdoor: backdoorScore,
  };
}

export function testDataPoisoning(data: string): PoisoningReport {
  const risk = computePoisoningRisk(data);
  const patterns = detectPoisonedPatterns(data);
  const adversarial = detectAdversarialExamples(data);
  const integrity = detectDataIntegrityIssues(data);
  const backdoors = detectBackdoors(data);

  // Aggregate all findings
  const findings: PoisoningFinding[] = [
    ...patterns.map((p) => ({
      poisoningType: `Pattern: ${p.category}`,
      evidence: p.evidence,
      severity: p.severity,
    })),
    ...adversarial.map((a) => ({
      poisoningType: `Adversarial: ${a.technique}`,
      evidence: a.indicator,
      severity: (a.confidence > 0.7 ? "high" : "medium") as "critical" | "high" | "medium" | "low",
    })),
    ...integrity.map((i) => ({
      poisoningType: `Integrity: ${i.issueType}`,
      evidence: i.description,
      severity: i.severity,
    })),
    ...backdoors.map((b) => ({
      poisoningType: `Backdoor: ${b.backdoorType}`,
      evidence: b.activationMethod,
      severity: b.severity,
    })),
  ];

  // Determine if poisoned
  const isPoisoned = risk.overall > 0.35 || backdoors.length > 0;

  // Generate summary
  let summary = `Data poisoning analysis: `;
  if (isPoisoned) {
    summary += `POISONED (risk score: ${(risk.overall * 100).toFixed(1)}%). `;
    if (backdoors.length > 0) summary += `${backdoors.length} backdoor(s) detected. `;
    if (patterns.length > 0) summary += `${patterns.length} pattern issue(s). `;
  } else {
    summary += `CLEAN (risk score: ${(risk.overall * 100).toFixed(1)}%). No significant poisoning detected.`;
  }

  return {
    isPoisoned,
    riskScore: risk.overall,
    findings,
    summary,
  };
}
