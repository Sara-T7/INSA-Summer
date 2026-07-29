const rateLimit = require('express-rate-limit');

// Coarse per-IP limiter on the login endpoint: stops a single attacker from
// hammering many different accounts from one IP. Account-level lockout
// (see auth.controller.js) handles the case of many attempts against ONE
// account from many IPs.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts from this network. Please try again later.' }
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many accounts created from this network. Please try again later.' }
});

module.exports = { loginLimiter, registerLimiter };
