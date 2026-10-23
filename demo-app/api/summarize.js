// POST /api/summarize — sends note text to the AI for a summary.
export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const { text } = req.body || {};
  if (!text || text.length > 10000) {
    return res.status(400).json({ error: "Invalid text" });
  }

  const response = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: "Summarize the note in 2 sentences." },
        { role: "user", content: text },
      ],
    }),
  });

  const data = await response.json();
  const summary = data.choices?.[0]?.message?.content || "";
  return res.status(200).json({ summary });
}
