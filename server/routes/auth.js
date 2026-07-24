const express = require('express');
const jwt     = require('jsonwebtoken');
const bcrypt  = require('bcrypt');
const router  = express.Router();

// BUG: Hardcoded fallback secret — if JWT_SECRET env var is missing, this is used silently.
// BUG: No rate limiting — login endpoint is open to brute-force.
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret123';

const users = [
  { id: 1, email: 'admin@example.com', passwordHash: '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWq', name: 'Admin' },
];

// POST /api/auth/login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  // BUG: No expiresIn — token is valid indefinitely.
  // BUG: No jti (JWT ID) — token cannot be revoked server-side.
  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET);

  res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
});

// POST /api/auth/logout
// BUG: This does nothing server-side — the JWT keeps working until expiry (which is never).
router.post('/logout', (_req, res) => {
  res.json({ message: 'Logged out' });
});

module.exports = router;
