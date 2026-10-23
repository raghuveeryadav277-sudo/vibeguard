// VULN: missing-security-headers
// Fixture: Express-style server with no security headers (no helmet, no header-setting calls)

const express = require('express');

const app = express();

app.use(express.json());

app.get('/', (req, res) => {
  res.send('Hello from sast-app fixture');
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
