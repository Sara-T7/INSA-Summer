const express = require('express');
const router = express.Router();
const { register, login, googleLogin, refresh, logout } = require('../controllers/auth.controller');
const { loginLimiter, registerLimiter } = require('../middleware/rateLimiter');

router.post('/register', registerLimiter, register);
router.post('/login', loginLimiter, login);
router.post('/google', loginLimiter, googleLogin);
router.post('/refresh', refresh);
router.post('/logout', logout);

module.exports = router;
