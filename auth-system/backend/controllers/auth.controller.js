const bcrypt = require('bcrypt');
const { OAuth2Client } = require('google-auth-library');
const pool = require('../config/db');
const { passwordIssues, isValidEmail } = require('../utils/validators');
const { signAccessToken, generateRefreshToken, hashToken } = require('../utils/tokens');
const { getClientIp, getUserAgent } = require('../utils/deviceInfo');

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const MAX_FAILED_ATTEMPTS = 5;
const LOCK_MINUTES = 5;
const REFRESH_TOKEN_TTL_DAYS = Number(process.env.REFRESH_TOKEN_TTL_DAYS || 30);
const BCRYPT_ROUNDS = 12;

const refreshCookieOptions = () => ({
  httpOnly: true,
  secure: process.env.COOKIE_SECURE === 'true',
  sameSite: 'lax',
  path: '/api/auth',
  maxAge: REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000
});

async function logAttempt(email, ip, success) {
  await pool.query(
    'INSERT INTO login_attempts (email, ip_address, success) VALUES (?, ?, ?)',
    [email, ip, success]
  );
}

// Creates a session row + sets the refresh cookie + returns a fresh access token.
async function issueSession(res, req, user) {
  const ip = getClientIp(req);
  const userAgent = getUserAgent(req);

  // Suspicious if this user has logged in before, but never from this
  // exact IP + user-agent combination.
  const [prior] = await pool.query(
    'SELECT id FROM sessions WHERE user_id = ? AND ip_address = ? AND user_agent = ? LIMIT 1',
    [user.id, ip, userAgent]
  );
  const [anyPrior] = await pool.query(
    'SELECT id FROM sessions WHERE user_id = ? LIMIT 1',
    [user.id]
  );
  const isSuspicious = anyPrior.length > 0 && prior.length === 0;

  const rawRefreshToken = generateRefreshToken();
  const refreshHash = hashToken(rawRefreshToken);

  await pool.query(
    `INSERT INTO sessions (user_id, refresh_token_hash, user_agent, ip_address, is_suspicious)
     VALUES (?, ?, ?, ?, ?)`,
    [user.id, refreshHash, userAgent, ip, isSuspicious]
  );

  res.cookie('refreshToken', rawRefreshToken, refreshCookieOptions());
  const accessToken = signAccessToken(user);

  return { accessToken, isSuspicious };
}

async function register(req, res) {
  try {
    const { email, password, name } = req.body;

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Please provide a valid email address.' });
    }
    const issues = passwordIssues(password);
    if (issues.length) {
      return res.status(400).json({ error: `Password must contain ${issues.join(', ')}.` });
    }

    const [existing] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
    if (existing.length) {
      return res.status(409).json({ error: 'An account with that email already exists.' });
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const [result] = await pool.query(
      'INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)',
      [email, passwordHash, name || null]
    );

    const user = { id: result.insertId, email };
    const { accessToken, isSuspicious } = await issueSession(res, req, user);

    return res.status(201).json({ accessToken, user: { id: user.id, email, name: name || null }, isSuspicious });
  } catch (err) {
    console.error('register error:', err);
    return res.status(500).json({ error: 'Something went wrong creating your account.' });
  }
}

async function login(req, res) {
  const { email, password } = req.body;
  const ip = getClientIp(req);

  try {
    if (!isValidEmail(email) || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    const user = rows[0];

    // Deliberately vague error messages below - never reveal whether the
    // email exists, to avoid account enumeration.
    if (!user || !user.password_hash) {
      await logAttempt(email, ip, false);
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    if (user.lock_until && new Date(user.lock_until) > new Date()) {
      await logAttempt(email, ip, false);
      const minutesLeft = Math.ceil((new Date(user.lock_until) - new Date()) / 60000);
      return res.status(423).json({ error: `Account temporarily locked. Try again in ${minutesLeft} minute(s).` });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);

    if (!validPassword) {
      const attempts = user.failed_login_attempts + 1;
      const lockUntil = attempts >= MAX_FAILED_ATTEMPTS
        ? new Date(Date.now() + LOCK_MINUTES * 60000)
        : null;

      await pool.query(
        'UPDATE users SET failed_login_attempts = ?, lock_until = ? WHERE id = ?',
        [attempts, lockUntil, user.id]
      );
      await logAttempt(email, ip, false);

      if (lockUntil) {
        return res.status(423).json({ error: `Too many failed attempts. Account locked for ${LOCK_MINUTES} minutes.` });
      }
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // Success: reset lockout counters.
    await pool.query(
      'UPDATE users SET failed_login_attempts = 0, lock_until = NULL WHERE id = ?',
      [user.id]
    );
    await logAttempt(email, ip, true);

    const { accessToken, isSuspicious } = await issueSession(res, req, user);
    return res.json({
      accessToken,
      user: { id: user.id, email: user.email, name: user.name },
      isSuspicious
    });
  } catch (err) {
    console.error('login error:', err);
    return res.status(500).json({ error: 'Something went wrong logging you in.' });
  }
}

async function googleLogin(req, res) {
  try {
    const { idToken } = req.body;
    if (!idToken) return res.status(400).json({ error: 'Missing Google idToken.' });

    const ticket = await googleClient.verifyIdToken({
      idToken,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    const payload = ticket.getPayload();
    const { sub: googleId, email, name } = payload;

    if (!email) return res.status(400).json({ error: 'Google account has no email.' });

    let [rows] = await pool.query('SELECT * FROM users WHERE google_id = ? OR email = ?', [googleId, email]);
    let user = rows[0];

    if (!user) {
      const [result] = await pool.query(
        'INSERT INTO users (email, google_id, name) VALUES (?, ?, ?)',
        [email, googleId, name || null]
      );
      user = { id: result.insertId, email, name };
    } else if (!user.google_id) {
      // Link Google to an existing password account with the same email.
      await pool.query('UPDATE users SET google_id = ? WHERE id = ?', [googleId, user.id]);
    }

    const { accessToken, isSuspicious } = await issueSession(res, req, user);
    return res.json({ accessToken, user: { id: user.id, email: user.email, name: user.name }, isSuspicious });
  } catch (err) {
    console.error('googleLogin error:', err);
    return res.status(401).json({ error: 'Google sign-in failed.' });
  }
}

async function refresh(req, res) {
  try {
    const rawToken = req.cookies.refreshToken;
    if (!rawToken) return res.status(401).json({ error: 'No refresh token provided.' });

    const tokenHash = hashToken(rawToken);
    const [rows] = await pool.query(
      `SELECT s.*, u.email, u.name FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.refresh_token_hash = ? AND s.revoked_at IS NULL LIMIT 1`,
      [tokenHash]
    );
    const session = rows[0];
    if (!session) return res.status(401).json({ error: 'Invalid or expired session.' });

    // Rotate: revoke the old refresh token and issue a brand new one.
    // This limits the damage if a refresh token is ever stolen/replayed.
    await pool.query('UPDATE sessions SET revoked_at = NOW() WHERE id = ?', [session.id]);

    const user = { id: session.user_id, email: session.email, name: session.name };
    const { accessToken } = await issueSession(res, req, user);

    return res.json({ accessToken, user: { id: user.id, email: user.email, name: user.name } });
  } catch (err) {
    console.error('refresh error:', err);
    return res.status(500).json({ error: 'Could not refresh session.' });
  }
}

async function logout(req, res) {
  try {
    const rawToken = req.cookies.refreshToken;
    if (rawToken) {
      const tokenHash = hashToken(rawToken);
      await pool.query('UPDATE sessions SET revoked_at = NOW() WHERE refresh_token_hash = ?', [tokenHash]);
    }
    res.clearCookie('refreshToken', { path: '/api/auth' });
    return res.json({ ok: true });
  } catch (err) {
    console.error('logout error:', err);
    return res.status(500).json({ error: 'Logout failed.' });
  }
}

module.exports = { register, login, googleLogin, refresh, logout };
