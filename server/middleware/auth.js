const jwt    = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret123';

// BUG: Same hardcoded fallback as auth.js — split across two files, easy to miss in review.
// BUG: No check that token hasn't been tampered with beyond signature (no aud/iss claims).
// BUG: Errors are swallowed with a generic 401 — impossible to distinguish expired vs tampered.

module.exports = function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'No token' });

  const token = authHeader.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};
