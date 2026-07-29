// Small fetch wrapper shared by all pages.
// Access token lives only in memory + sessionStorage (short-lived, 15 min).
// The long-lived refresh token lives in an httpOnly cookie the JS never touches.

const Auth = {
  getAccessToken() {
    return sessionStorage.getItem('accessToken');
  },
  setAccessToken(token) {
    if (token) sessionStorage.setItem('accessToken', token);
    else sessionStorage.removeItem('accessToken');
  },
  setUser(user) {
    if (user) sessionStorage.setItem('user', JSON.stringify(user));
    else sessionStorage.removeItem('user');
  },
  getUser() {
    const raw = sessionStorage.getItem('user');
    return raw ? JSON.parse(raw) : null;
  },
  clear() {
    sessionStorage.removeItem('accessToken');
    sessionStorage.removeItem('user');
  }
};

async function apiFetch(path, options = {}, retry = true) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  const token = Auth.getAccessToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers,
    credentials: 'include' // send/receive the httpOnly refresh cookie
  });

  // Access token expired -> try silent refresh once, then retry original call.
  if (res.status === 401 && retry) {
    const refreshed = await tryRefresh();
    if (refreshed) return apiFetch(path, options, false);
  }

  return res;
}

async function tryRefresh() {
  try {
    const res = await fetch(`${API_BASE_URL}/auth/refresh`, {
      method: 'POST',
      credentials: 'include'
    });
    if (!res.ok) return false;
    const data = await res.json();
    Auth.setAccessToken(data.accessToken);
    Auth.setUser(data.user);
    return true;
  } catch {
    return false;
  }
}
