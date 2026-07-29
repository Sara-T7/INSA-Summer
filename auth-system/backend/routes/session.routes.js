const express = require('express');
const router = express.Router();
const { listSessions, revokeSession } = require('../controllers/session.controller');
const { requireAuth } = require('../middleware/auth.middleware');

router.get('/', requireAuth, listSessions);
router.delete('/:id', requireAuth, revokeSession);

module.exports = router;
