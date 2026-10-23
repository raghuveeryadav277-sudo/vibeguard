// Clean App — AI chat route (protected)
// Calls an AI provider, but is guarded by auth + rate limit checks.

const OPENAI_API_KEY = process.env.OPENAI_API_KEY;

// Simple in-memory rate limit: max 20 requests per minute per user.
// This is a basic rate limit for the fixture; production would use Redis.
const requestCounts = new Map();
function isRateLimited(userId) {
  const now = Date.now();
  const windowMs = 60_000;
  const entry = requestCounts.get(userId) || { count: 0, windowStart: now };
  if (now - entry.windowStart > windowMs) {
    entry.count = 0;
    entry.windowStart = now;
  }
  entry.count += 1;
  requestCounts.set(userId, entry);
  return entry.count > 20;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Authorization check — required before any AI call.
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const userId = authHeader.slice('Bearer '.length);

  // Enforce rate limit before spending on AI calls.
  if (isRateLimited(userId)) {
    return res.status(429).json({ error: 'Too many requests — rate limit exceeded' });
  }

  const { message } = req.body || {};
  if (!message || typeof message !== 'string') {
    return res.status(400).json({ error: 'message is required' });
  }

  const response = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${OPENAI_API_KEY}`,
    },
    body: JSON.stringify({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: message }],
    }),
  });

  const data = await response.json();
  return res.status(200).json(data);
}
