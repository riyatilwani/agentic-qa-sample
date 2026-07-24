// Frontend-safe config — only public values.
// Never put secrets here; this ships to the browser.

const config = {
  apiBaseUrl: process.env.REACT_APP_API_URL || 'http://localhost:3001',
  appName:    'Agentic QA Sample',
  features: {
    payments: process.env.REACT_APP_PAYMENTS_ENABLED === 'true',
  },
};

export default config;
