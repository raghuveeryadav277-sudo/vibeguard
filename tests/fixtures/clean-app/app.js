// Clean App — main client/server logic
// All secrets are read from environment variables. No hardcoded secrets.

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const API_BASE = process.env.API_BASE_URL || 'https://api.example.com';

async function fetchNote(noteId, sessionToken) {
  // Parameterized fetch — values are passed as structured params, not string-built URLs with secrets.
  const params = new URLSearchParams({ id: String(noteId) });
  const res = await fetch(`${API_BASE}/notes?${params.toString()}`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${sessionToken}`,
      apikey: SUPABASE_ANON_KEY,
    },
  });
  if (!res.ok) throw new Error('Failed to fetch note');
  return res.json();
}

async function createNote(title, body, sessionToken) {
  const res = await fetch(`${API_BASE}/notes`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${sessionToken}`,
    },
    body: JSON.stringify({ title, body }),
  });
  if (!res.ok) throw new Error('Failed to create note');
  return res.json();
}

function renderNote(el, note) {
  // Safe rendering only.
  el.textContent = note.title;
}

module.exports = { fetchNote, createNote, renderNote };
