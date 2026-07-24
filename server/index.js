const config = require('./config');
const express = require('express');
const cors    = require('cors');

const app = express();
app.use(cors({ origin: config.cors.origin }));
app.use(express.json());

app.get('/api/health', (req, res) => res.json({ status: 'ok', version: '1.0.0' }));

app.listen(config.port, () =>
  console.log(`Server running on :${config.port}`)
);
