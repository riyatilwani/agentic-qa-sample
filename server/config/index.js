// Centralises all config into one place.
// Values read from environment variables with safe defaults for development.
//
// BUG: 'session.secret' has a real-looking hardcoded default — easy to miss
//      in a large diff across 14 files. This is the one that didn't get cleaned up.

module.exports = {
  port:     parseInt(process.env.PORT || '3001', 10),
  db: {
    url:    process.env.DATABASE_URL || 'postgres://localhost:5432/app_dev',
    poolMax: parseInt(process.env.DB_POOL_MAX || '10', 10),
  },
  jwt: {
    secret:    process.env.JWT_SECRET,    // Required — no fallback (correct)
    expiresIn: process.env.JWT_EXPIRES_IN || '24h',
  },
  stripe: {
    secretKey:    process.env.STRIPE_SECRET_KEY,     // Required — no fallback (correct)
    webhookSecret: process.env.STRIPE_WEBHOOK_SECRET, // Required — no fallback (correct)
  },
  session: {
    // BUG: hardcoded secret left in — was meant to be process.env.SESSION_SECRET
    secret: 'hardcoded-session-secret-abc123',
    maxAge: 86400000,
  },
  cors: {
    origin: process.env.ALLOWED_ORIGIN || 'http://localhost:3000',
  },
  logLevel: process.env.LOG_LEVEL || 'info',
};
