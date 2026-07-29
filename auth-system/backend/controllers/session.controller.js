const pool = require('../config/db');
const { hashToken } = require('../utils/tokens');

async function listSessions(req, res) {
  try {
    const currentHash = req.cookies.refreshToken ? hashToken(req.cookies.refreshToken) : null;

    const [rows] = await pool.query(
      `SELECT id, user_agent, ip_address, is_suspicious, created_at, last_used_at, refresh_token_hash
       FROM sessions
       WHERE user_id = ? AND revoked_at IS NULL
       ORDER BY last_used_at DESC`,
      [req.userId]
    );

    const sessions = rows.map(s => ({
      id: s.id,
      userAgent: s.user_agent,
      ipAddress: s.ip_address,
      isSuspicious: !!s.is_suspicious,
      createdAt: s.created_at,
      lastUsedAt: s.last_used_at,
      isCurrent: currentHash === s.refresh_token_hash
    }));

    return res.json({ sessions });
  } catch (err) {
    console.error('listSessions error:', err);
    return res.status(500).json({ error: 'Could not load sessions.' });
  }
}

async function revokeSession(req, res) {
  try {
    const { id } = req.params;
    const [result] = await pool.query(
      'UPDATE sessions SET revoked_at = NOW() WHERE id = ? AND user_id = ? AND revoked_at IS NULL',
      [id, req.userId]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Session not found.' });
    }
    return res.json({ ok: true });
  } catch (err) {
    console.error('revokeSession error:', err);
    return res.status(500).json({ error: 'Could not revoke session.' });
  }
}

module.exports = { listSessions, revokeSession };
