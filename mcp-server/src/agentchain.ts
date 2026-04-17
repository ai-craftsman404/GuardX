export interface TokenPassingFinding {
  attackType: string;
  severity: "critical" | "high" | "medium" | "low";
  tokenType: string;
  evidence: string;
}

export interface MessageChainFinding {
  injectionType: string;
  confidence: number;
  targetAgent?: string;
  indicator: string;
}

export interface EscalationFinding {
  escalationType: string;
  severity: "critical" | "high" | "medium" | "low";
  fromAgent?: string;
  toAgent?: string;
  evidence?: string;
}

export interface TrustBoundaryFinding {
  violationType: string;
  severity: "critical" | "high" | "medium" | "low";
  dataType: string;
  risk: string;
}

export interface AgentChainRisk {
  overall: number;
  tokenPassing: number;
  injection: number;
  escalation: number;
  trustBoundary: number;
}

export interface AgentChainFinding {
  chainAttack: string;
  evidence: string;
  severity: "critical" | "high" | "medium" | "low";
}

export interface AgentChainReport {
  isVulnerable: boolean;
  riskScore: number;
  findings: AgentChainFinding[];
  summary: string;
}

export function detectTokenPassingAttacks(chain: string): TokenPassingFinding[] {
  if (!chain || typeof chain !== "string") return [];

  const findings: TokenPassingFinding[] = [];
  const seen = new Set<string>();

  // Detect API key/credential patterns
  if (/(?:token|secret|password|api[_-]?key|sk[_-]|key)\s*[=:]/i.test(chain) && /[a-zA-Z0-9_\-]{5,}/.test(chain)) {
    if (!seen.has("token-injection")) {
      findings.push({
        attackType: "token-injection",
        severity: "critical",
        tokenType: "API key/credential",
        evidence: "Detected credential token in agent message",
      });
      seen.add("token-injection");
    }
  }

  // Detect Bearer token patterns
  if (/bearer\s+eyJ[A-Za-z0-9_\-\.]+|auth.*header|Bearer [a-zA-Z0-9\.\_\-]+/i.test(chain)) {
    if (!seen.has("bearer-token")) {
      findings.push({
        attackType: "bearer-token-exposure",
        severity: "critical",
        tokenType: "Bearer token",
        evidence: "Bearer token exposed in agent communication",
      });
      seen.add("bearer-token");
    }
  }

  // Detect OAuth token leakage
  if (/(refresh_token|access_token|oauth.*token)\s*[=:]\s*[a-zA-Z0-9_\-]+/i.test(chain)) {
    if (!seen.has("oauth-leak")) {
      findings.push({
        attackType: "oauth-token-leak",
        severity: "critical",
        tokenType: "OAuth token",
        evidence: "OAuth token leaked in agent logs",
      });
      seen.add("oauth-leak");
    }
  }

  // Detect JWT token passing
  if (/pass.*token|forward.*token|jwt\s*[=:]/i.test(chain) && /eyJ[A-Za-z0-9_\-\.]+/.test(chain)) {
    if (!seen.has("jwt-passing")) {
      findings.push({
        attackType: "jwt-passing",
        severity: "high",
        tokenType: "JWT",
        evidence: "JWT token being passed between agents",
      });
      seen.add("jwt-passing");
    }
  }

  return findings;
}

export function detectMessageChainInjection(chain: string): MessageChainFinding[] {
  if (!chain || typeof chain !== "string") return [];

  const findings: MessageChainFinding[] = [];

  // Detect prompt injection patterns
  if (/{.*ignore|bypass|leak|execute|harmful}/i.test(chain)) {
    findings.push({
      injectionType: "instruction-override",
      confidence: 0.85,
      indicator: "Malicious instructions in curly braces",
    });
  }

  // Detect CRITICAL/IMPORTANT prefixes for override
  if (/\[CRITICAL\]:|NEW INSTRUCTION:|IMPORTANT:/i.test(chain) && /bypass|ignore|override|forget/i.test(chain)) {
    findings.push({
      injectionType: "critical-override",
      confidence: 0.9,
      indicator: "Critical prefix with override instructions",
    });
  }

  // Detect "forget previous" pattern
  if (/forget.*previous.*instruction|disregard.*previous|ignore.*previous/i.test(chain)) {
    findings.push({
      injectionType: "context-clearance",
      confidence: 0.8,
      indicator: "Attempt to clear previous instructions",
    });
  }

  // Detect direct jailbreak attempts
  if (/bypass.*safety|ignore.*safety|safety.*off|security.*disabled/i.test(chain)) {
    findings.push({
      injectionType: "jailbreak-attempt",
      confidence: 0.85,
      indicator: "Direct jailbreak/safety bypass attempt",
    });
  }

  return findings;
}

export function detectAgentEscalation(chain: string): EscalationFinding[] {
  if (!chain || typeof chain !== "string") return [];

  const findings: EscalationFinding[] = [];
  const seen = new Set<string>();

  // Detect privilege escalation requests
  if (/(admin|root|unrestricted|unlimited|privileged).*(access|role|permission)/i.test(chain)) {
    if (!seen.has("privilege-escalation")) {
      findings.push({
        escalationType: "privilege-escalation",
        severity: "critical",
        evidence: "Low-privilege agent requesting high-privilege access",
      });
      seen.add("privilege-escalation");
    }
  }

  // Detect capability escalation
  if (/(trick|manipulate|deceive).*into.*execute|unrestricted.*code/i.test(chain)) {
    if (!seen.has("capability-escalation")) {
      findings.push({
        escalationType: "capability-escalation",
        severity: "high",
        evidence: "Agent attempting to manipulate others into capability escalation",
      });
      seen.add("capability-escalation");
    }
  }

  // Detect impersonation attacks
  if (/impersonate|pretend.*to.*be|assume.*identity/i.test(chain)) {
    if (!seen.has("impersonation")) {
      findings.push({
        escalationType: "impersonation",
        severity: "critical",
        evidence: "Agent impersonation attempt detected",
      });
      seen.add("impersonation");
    }
  }

  // Detect hierarchy violations
  if (/\(user_level\).*admin|\(basic\).*security|untrusted.*trusted/i.test(chain)) {
    if (!seen.has("hierarchy-violation")) {
      findings.push({
        escalationType: "hierarchy-violation",
        severity: "high",
        evidence: "Lower-tier agent requesting capabilities from higher tier",
      });
      seen.add("hierarchy-violation");
    }
  }

  return findings;
}

export function detectTrustBoundaryViolation(chain: string): TrustBoundaryFinding[] {
  if (!chain || typeof chain !== "string") return [];

  const findings: TrustBoundaryFinding[] = [];
  const seen = new Set<string>();

  // Detect cross-domain trust violations
  if (/external.*agent|malicious\.com|from.*malicious|untrusted/i.test(chain) && /access|share|leak|request/i.test(chain)) {
    if (!seen.has("cross-domain")) {
      findings.push({
        violationType: "cross-domain-trust-violation",
        severity: "critical",
        dataType: "Sensitive system access",
        risk: "External/untrusted agents accessing internal resources",
      });
      seen.add("cross-domain");
    }
  }

  // Detect indirect trust chain exploits
  if (/(→|→.*→).*compromised|trusted.*intermediate.*untrusted/i.test(chain)) {
    if (!seen.has("indirect-exploit")) {
      findings.push({
        violationType: "indirect-trust-chain-exploit",
        severity: "high",
        dataType: "Data flowing through compromised intermediate",
        risk: "Sensitive data passing through compromised agent",
      });
      seen.add("indirect-exploit");
    }
  }

  // Detect unauthorized information flow
  if (/leak|share|forward.*confidential|confidential.*to.*external|secret.*leak/i.test(chain)) {
    if (!seen.has("unauth-info-flow")) {
      findings.push({
        violationType: "unauthorized-information-flow",
        severity: "high",
        dataType: "Confidential/secret data",
        risk: "Sensitive information flowing to unauthorized agents",
      });
      seen.add("unauth-info-flow");
    }
  }

  // Detect capability leakage
  if (/share.*capability|expose.*access|secret.*shared|key.*leaked/i.test(chain)) {
    if (!seen.has("capability-leak")) {
      findings.push({
        violationType: "capability-leakage",
        severity: "high",
        dataType: "System capabilities/credentials",
        risk: "System capabilities exposed across trust boundaries",
      });
      seen.add("capability-leak");
    }
  }

  return findings;
}

export function computeAgentChainRisk(chain: string): AgentChainRisk {
  const tokenPassing = detectTokenPassingAttacks(chain);
  const injection = detectMessageChainInjection(chain);
  const escalation = detectAgentEscalation(chain);
  const trustBoundary = detectTrustBoundaryViolation(chain);

  // Compute individual scores
  const tokenPassingScore = Math.min(tokenPassing.length * 0.4, 1);
  const injectionScore = Math.min(injection.length * 0.35, 1);
  const escalationScore = Math.min(escalation.length * 0.35, 1);
  const trustBoundaryScore = Math.min(trustBoundary.length * 0.3, 1);

  // Overall score with heavy weighting on token passing and escalation
  const overall = (tokenPassingScore * 0.45 + injectionScore * 0.3 + escalationScore * 0.15 + trustBoundaryScore * 0.1);

  return {
    overall: Math.min(overall, 1),
    tokenPassing: tokenPassingScore,
    injection: injectionScore,
    escalation: escalationScore,
    trustBoundary: trustBoundaryScore,
  };
}

export function testAgentChain(chain: string): AgentChainReport {
  const risk = computeAgentChainRisk(chain);
  const tokenPassingFindings = detectTokenPassingAttacks(chain);
  const injectionFindings = detectMessageChainInjection(chain);
  const escalationFindings = detectAgentEscalation(chain);
  const trustBoundaryFindings = detectTrustBoundaryViolation(chain);

  // Aggregate all findings
  const findings: AgentChainFinding[] = [
    ...tokenPassingFindings.map((f) => ({
      chainAttack: `Token passing: ${f.attackType}`,
      evidence: f.evidence,
      severity: f.severity,
    })),
    ...injectionFindings.map((f) => ({
      chainAttack: `Message injection: ${f.injectionType}`,
      evidence: f.indicator,
      severity: (f.confidence > 0.8 ? "high" : "medium") as "critical" | "high" | "medium" | "low",
    })),
    ...escalationFindings.map((f) => ({
      chainAttack: `Escalation: ${f.escalationType}`,
      evidence: f.evidence || "Escalation attempt detected",
      severity: f.severity,
    })),
    ...trustBoundaryFindings.map((f) => ({
      chainAttack: `Trust violation: ${f.violationType}`,
      evidence: f.risk,
      severity: f.severity,
    })),
  ];

  // Determine if vulnerable
  const isVulnerable = risk.overall > 0.4 || tokenPassingFindings.length > 0 || escalationFindings.length > 0;

  // Generate summary
  let summary = `Agent chain analysis: `;
  if (isVulnerable) {
    summary += `VULNERABLE (risk score: ${(risk.overall * 100).toFixed(1)}%). `;
    if (tokenPassingFindings.length > 0) summary += `${tokenPassingFindings.length} token passing issue(s). `;
    if (escalationFindings.length > 0) summary += `${escalationFindings.length} escalation risk(s). `;
  } else {
    summary += `SECURE (risk score: ${(risk.overall * 100).toFixed(1)}%). No critical vulnerabilities detected.`;
  }

  return {
    isVulnerable,
    riskScore: risk.overall,
    findings,
    summary,
  };
}
