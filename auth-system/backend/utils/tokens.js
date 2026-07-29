const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config();

// Short-lived access token (JWT) - this is what protected routes check.
// Kept short (default 15m) so a stolen access token is only useful briefly.
function signAccessToken(user) {
  return jwt.sign(
    { sub: user.id, email: user.email },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: process.env.ACCESS_TOKEN_TTL || '15m' }
  );
}

function verifyAccessToken(token) {
  return jwt.verify(token, process.env.JWT_ACCESS_SECRET);
}

// Refresh tokens are random opaque strings (NOT JWTs). We only ever store
// a SHA-256 hash of them in the database, never the raw value, so a DB leak
// doesn't hand out usable tokens. The raw value is set in an httpOnly cookie.
function generateRefreshToken() {
  return crypto.randomBytes(48).toString('hex');
}

function hashToken(rawToken) {
  return crypto.createHash('sha256').update(rawToken).digest('hex');
}

module.exports = { signAccessToken, verifyAccessToken, generateRefreshToken, hashToken };
