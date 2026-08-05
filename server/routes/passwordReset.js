const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const router = express.Router();

// This PR doesn't have a shared user store to import yet — auth.js's
// `users` array is module-local, not exported. Mirroring its one seed
// record here for the demo; a real change would first extract a shared
// user module rather than let two files hold separate copies.
const users = [
  { id: 1, email: 'admin@example.com', passwordHash: '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWq', name: 'Admin' },
];

// Demo in-memory store for reset tokens. A real deployment would persist
// this in the same DB as users, with a unique index on token and a
// TTL/cleanup job for expired rows.
const resetTokens = new Map(); // token -> { userId, expiresAt }

const RESET_TOKEN_TTL_MS = 15 * 60 * 1000; // 15 minutes
const MIN_PASSWORD_LENGTH = 10;

// POST /api/auth/request-reset
// Always responds with the same generic message whether or not the email
// matches an account — a distinguishable response here would let a caller
// enumerate registered emails.
router.post('/request-reset', async (req, res) => {
  const { email } = req.body || {};
  const genericResponse = { message: 'If that email is registered, a reset link has been sent.' };

  if (!email) return res.status(400).json({ error: 'Email is required' });

  const user = users.find((u) => u.email === email);
  if (user) {
    const token = crypto.randomBytes(32).toString('hex');
    resetTokens.set(token, { userId: user.id, expiresAt: Date.now() + RESET_TOKEN_TTL_MS });

    // In production this token goes out over email, never in a response
    // body or a log line — only the fact that a reset was requested is
    // worth recording here.
    console.log(`Password reset requested for user id ${user.id}`);

    // TODO: wire up an email provider. For now the token exists only in
    // resetTokens, so reset-password is reachable in this demo via the
    // token returned by tests/fixtures, not a real email delivery path.
  }

  res.json(genericResponse);
});

// POST /api/auth/reset-password
router.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body || {};

  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Token and newPassword are required' });
  }
  if (newPassword.length < MIN_PASSWORD_LENGTH) {
    return res.status(400).json({ error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters` });
  }

  const entry = resetTokens.get(token);
  if (!entry || entry.expiresAt < Date.now()) {
    resetTokens.delete(token);
    return res.status(400).json({ error: 'Reset token is invalid or has expired' });
  }

  const user = users.find((u) => u.id === entry.userId);
  if (!user) {
    resetTokens.delete(token);
    return res.status(400).json({ error: 'Reset token is invalid or has expired' });
  }

  user.passwordHash = await bcrypt.hash(newPassword, 10);

  // Single-use: burn the token immediately so a captured/replayed token
  // can't reset the password a second time.
  resetTokens.delete(token);

  res.json({ message: 'Password has been reset' });
});

module.exports = router;
