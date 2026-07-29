require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const authRoutes = require('./routes/auth.routes');
const sessionRoutes = require('./routes/session.routes');
const { requireAuth } = require('./middleware/auth.middleware');

const app = express();

app.use(helmet());
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:5500',
  credentials: true // required so the httpOnly refresh cookie is sent/received
}));

app.use('/api/auth', authRoutes);
app.use('/api/sessions', sessionRoutes);

// Example of a "protected resource" - anything behind requireAuth needs a
// valid, unexpired access token in the Authorization header.
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ userId: req.userId, email: req.userEmail });
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Auth server running on http://localhost:${PORT}`));
