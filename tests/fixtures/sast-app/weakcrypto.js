// VULN: weak-crypto
// Fixture: Weak hashing (MD5) for passwords and insecure randomness for tokens

const crypto = require('crypto');

function hashPassword(password) {
  // Unsafe: MD5 is too weak/fast for password hashing
  return crypto.createHash('md5').update(password).digest('hex');
}

function generateToken() {
  // Unsafe: Math.random() is not cryptographically secure
  let token = '';
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < 32; i++) {
    token += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return token;
}

module.exports = { hashPassword, generateToken };
