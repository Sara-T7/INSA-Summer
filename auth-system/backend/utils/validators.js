const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Requirements: 8+ chars, at least one uppercase, one lowercase, one digit, one symbol.
function passwordIssues(password) {
  const issues = [];
  if (!password || password.length < 8) issues.push('at least 8 characters');
  if (!/[a-z]/.test(password)) issues.push('a lowercase letter');
  if (!/[A-Z]/.test(password)) issues.push('an uppercase letter');
  if (!/[0-9]/.test(password)) issues.push('a number');
  if (!/[^A-Za-z0-9]/.test(password)) issues.push('a special character');

  // Block a short list of extremely common passwords regardless of the above.
  const COMMON = ['password', '12345678', 'qwertyui', 'letmein1', 'password1'];
  if (password && COMMON.includes(password.toLowerCase())) {
    issues.push('a password that is not on the common-password list');
  }
  return issues;
}

function isValidEmail(email) {
  return typeof email === 'string' && EMAIL_RE.test(email) && email.length <= 255;
}

module.exports = { passwordIssues, isValidEmail };
