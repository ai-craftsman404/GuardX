export interface AuditExport {
  format: "json" | "csv" | "pdf";
  findings: unknown[];
  summary: string;
  exportDate: string;
}

export function generateAuditReport(findings: unknown[], format: "json" | "csv" | "pdf" = "json"): AuditExport {
  return {
    format,
    findings,
    summary: `Audit report with ${Array.isArray(findings) ? findings.length : 0} findings`,
    exportDate: new Date().toISOString(),
  };
}
