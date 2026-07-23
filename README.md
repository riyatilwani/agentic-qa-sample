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

## Open PRs (QA Demo Scenarios)

| PR | Description | Expected Tier | Expected Verdict |
|----|-------------|---------------|-----------------|
| #1 | Add user auth with token storage | FULL | BLOCK — XSS vulnerability |
| #2 | Optimise dashboard data fetch | LITE | Comments — missing DB index |
| #3 | Fix typo in README | TRIVIAL | Approved |
| #4 | Add payment intent creation | FULL | BLOCK — secret leaked, race condition |
| #5 | Refactor config to env vars | FULL | BLOCK — hardcoded secret in one file |
