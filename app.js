const express = require('express');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

// Example routes for testing
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (email === 'test@example.com' && password === 'password') {
    return res.json({ token: 'fake-jwt-token' });
  }
  return res.status(401).json({ message: 'Unauthorized' });
});

app.post('/upload', (req, res) => {
  if (!req.headers.authorization) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  // Fake success response
  return res.json({ message: 'File uploaded successfully' });
});

module.exports = app;