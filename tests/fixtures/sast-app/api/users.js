// VULN: missing-auth
// Fixture: Unprotected API route — no auth check, no AI call

const db = require('../db');

export default async function handler(req, res) {
  // No Authorization check, no session check — anyone can call this.
  if (req.method === 'GET') {
    const users = await db.query('SELECT * FROM users');
    return res.status(200).json(users);
  }

  if (req.method === 'POST') {
    const { name, email } = req.body;
    const created = await db.query(
      'INSERT INTO users (name, email) VALUES ($1, $2) RETURNING *',
      [name, email]
    );
    return res.status(201).json(created);
  }

  if (req.method === 'DELETE') {
    const { id } = req.body;
    await db.query('DELETE FROM users WHERE id = $1', [id]);
    return res.status(204).end();
  }

  return res.status(405).json({ error: 'Method not allowed' });
}
