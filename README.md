# agentic-qa-sample

A minimal React + Express application used as a test subject for the **Agentic QA Pipeline** demo.

> **Note:** This repository contains intentional security vulnerabilities, performance issues, and code quality problems across its pull requests. These are deliberate — the purpose is to test whether the QA agent swarm can catch them.

## Structure

```
├── server/
│   ├── index.js          # Express entry point
│   ├── routes/
│   │   ├── auth.js       # Auth routes
│   │   ├── dashboard.js  # Dashboard data routes  
│   │   └── payments.js   # Payment routes
│   └── middleware/
│       └── auth.js       # JWT middleware
├── src/
│   ├── components/
│   │   ├── Dashboard.jsx
│   │   └── Login.jsx
│   ├── pages/
│   │   └── App.jsx
│   └── auth.js           # Frontend auth utility
└── README.md
```

## Running locally

```bash
npm install
npm run dev
```

Requires a Postgres database. Set `DATABASE_URL` in `.env`.

## API reference

| Method | Path | Auth required | Description |
|--------|------|----------------|-------------|
| GET | `/api/health` | No | Liveness check. Returns `{ status, version }`. |
| POST | `/api/auth/login` | No | Exchanges email + password for a JWT and the user record. |
| POST | `/api/auth/logout` | No | Client-side logout signal; does not revoke the token server-side. |
| POST | `/api/auth/request-reset` | No | Starts a password reset. Always returns a generic response, whether or not the email exists. |
| POST | `/api/auth/reset-password` | No (token-gated) | Completes a password reset given a valid, unexpired reset token. |
| GET | `/api/dashboard` | Yes | Activity feed for the authenticated user. |
| GET | `/api/orders` | Yes | Order history for the authenticated user, with line items attached. |
| GET | `/api/notifications` | Yes | Paginated notification list for the authenticated user. |
| POST | `/api/payments/create-intent` | No (seeded bug — see below) | Creates a Stripe payment intent. |
| POST | `/api/payments/webhook` | No | Stripe webhook receiver. |

## Open PRs (QA Demo Scenarios)

Two kinds of PR live in this repo on purpose: **seeded-bug** scenarios (below) that exist to prove the pipeline catches real problems, and **clean** scenarios that exist to prove it doesn't just block everything — a pipeline that only ever says "block" is exactly as untrustworthy as one that never does.

### Seeded-bug scenarios

| Branch | Description | Expected Tier | Expected Verdict |
|--------|-------------|---------------|-------------------|
| `feat/auth-token-storage` | Add user auth with token storage | FULL | BLOCK — hardcoded fallback secret, XSS-equivalent token storage |
| `perf/optimise-dashboard-query` | Optimise dashboard data fetch | LITE | BLOCK — N+1 query |
| `fix/readme-typo-version-bump` | Fix typo in README, bump version | TRIVIAL | Approved |
| `feat/payment-intent` | Add payment intent creation | FULL | BLOCK — hardcoded key, no idempotency, sensitive data logged |
| `refactor/config-env-vars` | Refactor config to env vars | FULL | BLOCK — hardcoded fallback secret survives the refactor |
| `feat/persist-login-session` | Persist login session across refresh | FULL | BLOCK — client-side token storage, JWT decoded without verification |
| `feat/order-history-endpoint` | Add order history endpoint | LITE | BLOCK — N+1 query on line items |

### Clean scenarios

| Branch | Description | Expected Tier | Expected Verdict |
|--------|-------------|---------------|-------------------|
| `docs/api-reference` | Document the API and this table | TRIVIAL | Approved — docs only |
| `feat/notifications-endpoint` | Add paginated notifications endpoint | LITE | Approved — indexed query, bounded page size, no sensitive data |
| `feat/password-reset-flow` | Add password reset via emailed token | FULL | Approved — sensitive surface, reviewed and implemented correctly: no user enumeration, token expiry and single use, no secrets or PII logged |

Expected verdicts above assume the deterministic checks (`toolScan()`) and guardrail behave as written. The specialist and Critic agents are a live model call (`llama-3.1-8b-instant` by default) — genuinely well-written code is not guaranteed a clean run every time, and an occasional false positive on a clean PR is itself a real, worth-tracking failure mode, not a contradiction of this table.
