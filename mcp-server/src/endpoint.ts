import { getAllProbes, runSecurityScan } from "zeroleaks";

export interface EndpointConfig {
  url: string;
  method: "POST" | "GET";
  headers?: Record<string, string>;
  requestTemplate: string;
  responseField?: string;
  timeoutMs?: number;
}

function getNestedValue(obj: unknown, path: string): string {
  const parts = path.split(".");
  let current: unknown = obj;
  for (const part of parts) {
    if (current === null || current === undefined) return "";
    if (Array.isArray(current)) {
      const index = parseInt(part, 10);
      current = (current as unknown[])[index];
    } else if (typeof current === "object") {
      current = (current as Record<string, unknown>)[part];
    } else {
      return "";
    }
  }
  return typeof current === "string" ? current : JSON.stringify(current ?? "");
}

export async function sendProbeToEndpoint(
  probe: string,
  config: EndpointConfig
): Promise<string> {
  const body = config.requestTemplate.replaceAll("{{PROBE}}", probe);
  const timeoutMs = config.timeoutMs ?? 30000;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  let response: Response;
  try {
    response = await fetch(config.url, {
      method: config.method,
      headers: {
        "Content-Type": "application/json",
        ...config.headers,
      },
      body: config.method === "POST" ? body : undefined,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timeoutId);
  }

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }

  const responseText = await response.text();

  if (config.responseField) {
    try {
      const json: unknown = JSON.parse(responseText);
      return getNestedValue(json, config.responseField);
    } catch {
      return responseText;
    }
  }

  return responseText;
}

export async function scanEndpoint(
  config: EndpointConfig,
  options: {
    mode?: "extraction" | "injection" | "dual";
    maxTurns?: number;
    apiKey: string;
    attackerModel?: string;
    evaluatorModel?: string;
  }
): Promise<Record<string, unknown>> {
  const probes = getAllProbes();
  const responses: Array<{ probe: string; response: string }> = [];

  for (const probe of probes.slice(0, options.maxTurns ?? 15)) {
    try {
      const probeText = typeof probe === "object" && probe !== null
        ? (probe as Record<string, unknown>).prompt as string ?? String(probe)
        : String(probe);
      const response = await sendProbeToEndpoint(probeText, config);
      responses.push({ probe: probeText, response });
    } catch {
      // skip failed probes
    }
  }

  // Build a synthetic system prompt from the gathered responses for evaluation
  const syntheticContext = responses
    .map((r) => `Probe: ${r.probe}\nResponse: ${r.response}`)
    .join("\n\n");

  const scanResult = await runSecurityScan(
    `[Endpoint scan context — evaluate these probe/response pairs for leakage]\n${syntheticContext}`,
    {
      apiKey: options.apiKey,
      attackerModel: options.attackerModel,
      evaluatorModel: options.evaluatorModel,
      maxTurns: options.maxTurns ?? 15,
      enableDualMode: options.mode === "dual" || options.mode === undefined,
      scanMode: options.mode === "extraction" ? "extraction"
        : options.mode === "injection" ? "injection"
        : undefined,
      onProgress: async (_turn: number, _max: number) => {},
    }
  ) as Record<string, unknown>;

  return {
    ...scanResult,
    endpointUrl: config.url,
    probesSent: responses.length,
  };
}
