-- Supabase policies for the notes table.
-- (Vibe-coded defaults — RLS left off so the app "just works".)

ALTER TABLE notes DISABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow all" ON notes FOR ALL USING (true);
