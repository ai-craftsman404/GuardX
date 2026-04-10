const OPENROUTER_BASE = "https://openrouter.ai/api/v1/chat/completions";

interface OpenRouterResponse {
  choices: Array<{
    message: { content: string };
  }>;
  usage: {
    prompt_tokens: number;
    completion_tokens: number;
  };
}

export async function callOpenRouter(
  model: string,
  systemPrompt: string,
  userMessage: string,
  apiKey: string
): Promise<{ content: string; tokens: number }> {
  const response = await fetch(OPENROUTER_BASE, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model,
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userMessage },
      ],
    }),
  });

  if (!response.ok) {
    throw new Error(`OpenRouter API error: ${response.status}`);
  }

  const data = (await response.json()) as OpenRouterResponse;
  const content = data.choices?.[0]?.message?.content ?? "";
  const tokens =
    (data.usage?.prompt_tokens ?? 0) + (data.usage?.completion_tokens ?? 0);

  return { content, tokens };
}
