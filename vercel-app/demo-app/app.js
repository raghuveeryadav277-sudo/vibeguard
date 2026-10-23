// QuickNotes frontend — talks directly to Supabase from the browser.
const SUPABASE_URL = "https://xyzcompany.supabase.co";
const SUPABASE_SERVICE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJzZXJ2aWNlX3JvbGUiLCJleHAiOjQ3MzU5NzMyMDB9.ZEVNT19GQUtFX1NJR05BVFVSRS1hYmMxMjNYWVo";

async function loadNotes() {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/notes?select=*`, {
    headers: {
      apikey: SUPABASE_SERVICE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
    },
  });
  const notes = await res.json();
  renderNotes(notes);
}

async function saveNote(text) {
  await fetch(`${SUPABASE_URL}/rest/v1/notes`, {
    method: "POST",
    headers: {
      apikey: SUPABASE_SERVICE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ text }),
  });
  loadNotes();
}

async function summarizeWithAI(text) {
  const res = await fetch("/api/summarize", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text }),
  });
  const data = await res.json();
  document.getElementById("summary-output").innerText = data.summary || "No summary.";
}

document.getElementById("save-btn").addEventListener("click", () => {
  const text = document.getElementById("note-input").value;
  if (text.trim()) saveNote(text);
});
document.getElementById("summarize-btn").addEventListener("click", () => {
  const text = document.getElementById("note-input").value;
  if (text.trim()) summarizeWithAI(text);
});

loadNotes();
