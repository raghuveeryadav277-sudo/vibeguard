// VULN: sqli
// Fixture: SQL injection via string concatenation

const db = require('./db');

async function getUser(userId) {
  const query = "SELECT * FROM users WHERE id = " + userId;
  return db.query(query);
}

async function findByName(name) {
  const sql = "SELECT * FROM users WHERE name = '" + name + "'";
  return db.query(sql);
}

module.exports = { getUser, findByName };
