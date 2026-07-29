function getClientIp(req) {
  // Trust X-Forwarded-For only if you configure Express 'trust proxy' behind
  // a real reverse proxy. For local XAMPP/dev use, req.ip is fine.
  return req.ip || req.socket.remoteAddress || 'unknown';
}

function getUserAgent(req) {
  return (req.headers['user-agent'] || 'unknown').slice(0, 500);
}

module.exports = { getClientIp, getUserAgent };
