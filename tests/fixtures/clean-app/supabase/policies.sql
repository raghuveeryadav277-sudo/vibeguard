-- Clean App — Supabase Row Level Security policies
-- RLS is enabled and policies are restrictive (owner-only).

ALTER TABLE notes ENABLE ROW LEVEL SECURITY;

-- Users can only read their own notes.
CREATE POLICY "Users can read own notes"
  ON notes
  FOR SELECT
  USING (auth.uid() = user_id);

-- Users can only insert notes owned by themselves.
CREATE POLICY "Users can insert own notes"
  ON notes
  FOR INSERT
  WITH CHECK (auth.uid() = user_id);

-- Users can only update their own notes.
CREATE POLICY "Users can update own notes"
  ON notes
  FOR UPDATE
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- Users can only delete their own notes.
CREATE POLICY "Users can delete own notes"
  ON notes
  FOR DELETE
  USING (auth.uid() = user_id);
