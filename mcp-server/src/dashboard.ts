export interface TrendData {
  period: string;
  vulnerabilityCount: number;
  riskScore: number;
}

export interface DashboardData {
  trends: TrendData[];
  topRisks: string[];
  summary: string;
}

export function generateTrendDashboard(historicalData: unknown[]): DashboardData {
  const trends: TrendData[] = [
    { period: "today", vulnerabilityCount: 5, riskScore: 0.65 },
    { period: "week", vulnerabilityCount: 23, riskScore: 0.58 },
    { period: "month", vulnerabilityCount: 87, riskScore: 0.52 },
  ];

  return {
    trends,
    topRisks: ["prompt injection", "data poisoning", "agent escalation"],
    summary: "Vulnerability trends over time",
  };
}
