function fmtDate(d) {
  return new Date(d).toLocaleString();
}

async function loadMe() {
  const res = await apiFetch('/me');
  if (!res.ok) {
    window.location.href = 'index.html';
    return null;
  }
  return res.json();
}

async function loadSessions() {
  const res = await apiFetch('/sessions');
  const tbody = document.getElementById('sessionsBody');
  if (!res.ok) {
    tbody.innerHTML = '<tr><td colspan="5">Could not load sessions.</td></tr>';
    return;
  }
  const { sessions } = await res.json();

  tbody.innerHTML = sessions.map(s => `
    <tr data-id="${s.id}">
      <td>${escapeHtml(shortenUA(s.userAgent))}</td>
      <td>${escapeHtml(s.ipAddress)}</td>
      <td>${fmtDate(s.lastUsedAt)}</td>
      <td>
        ${s.isCurrent ? '<span class="badge current">This device</span>' : ''}
        ${s.isSuspicious ? '<span class="badge suspicious">Suspicious</span>' : ''}
      </td>
      <td>${s.isCurrent ? '' : `<button class="revoke" data-id="${s.id}">Revoke</button>`}</td>
    </tr>
  `).join('') || '<tr><td colspan="5" class="subtitle">No active sessions.</td></tr>';

  document.querySelectorAll('.revoke').forEach(btn => {
    btn.addEventListener('click', async () => {
      btn.disabled = true;
      const res = await apiFetch(`/sessions/${btn.dataset.id}`, { method: 'DELETE' });
      if (res.ok) {
        btn.closest('tr').remove();
      } else {
        btn.disabled = false;
      }
    });
  });
}

function shortenUA(ua) {
  if (!ua) return 'Unknown device';
  return ua.length > 60 ? ua.slice(0, 60) + '…' : ua;
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str ?? '';
  return div.innerHTML;
}

document.getElementById('logoutBtn').addEventListener('click', async () => {
  await apiFetch('/auth/logout', { method: 'POST' });
  Auth.clear();
  window.location.href = 'index.html';
});

(async function init() {
  // Try to establish a session (in case the access token is gone but the
  // refresh cookie is still valid, e.g. after a page reload).
  if (!Auth.getAccessToken()) {
    await tryRefresh();
  }

  const me = await loadMe();
  if (!me) return;

  const user = Auth.getUser();
  document.getElementById('greeting').textContent = `Welcome${user?.name ? ', ' + user.name : ''}`;
  document.getElementById('emailLine').textContent = me.email;

  if (sessionStorage.getItem('flagSuspicious')) {
    document.getElementById('suspiciousBox').classList.add('visible');
    sessionStorage.removeItem('flagSuspicious');
  }

  await loadSessions();
})();
