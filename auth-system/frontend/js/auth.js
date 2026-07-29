function showError(msg) {
  const box = document.getElementById('errorBox');
  if (!box) return;
  box.textContent = msg;
  box.classList.add('visible');
}
function hideError() {
  const box = document.getElementById('errorBox');
  if (box) box.classList.remove('visible');
}
function showWarning(msg) {
  const box = document.getElementById('warningBox');
  if (!box) return;
  box.textContent = msg;
  box.classList.add('visible');
}

async function handleAuthResponse(res) {
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || 'Something went wrong.');
  }
  Auth.setAccessToken(data.accessToken);
  Auth.setUser(data.user);
  if (data.isSuspicious) {
    sessionStorage.setItem('flagSuspicious', '1');
  }
  window.location.href = 'dashboard.html';
}

// ---- Email/password login ----
const loginForm = document.getElementById('loginForm');
if (loginForm) {
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideError();
    const submitBtn = document.getElementById('submitBtn');
    submitBtn.disabled = true;
    try {
      const res = await apiFetch('/auth/login', {
        method: 'POST',
        body: JSON.stringify({
          email: document.getElementById('email').value.trim(),
          password: document.getElementById('password').value
        })
      }, false);
      await handleAuthResponse(res);
    } catch (err) {
      showError(err.message);
    } finally {
      submitBtn.disabled = false;
    }
  });
}

// ---- Registration with live password strength meter ----
const registerForm = document.getElementById('registerForm');
if (registerForm) {
  const pwInput = document.getElementById('password');
  const fill = document.getElementById('strengthFill');

  pwInput.addEventListener('input', () => {
    const pw = pwInput.value;
    let score = 0;
    if (pw.length >= 8) score++;
    if (/[a-z]/.test(pw)) score++;
    if (/[A-Z]/.test(pw)) score++;
    if (/[0-9]/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;

    const pct = (score / 5) * 100;
    fill.style.width = `${pct}%`;
    fill.style.background = score <= 2 ? '#ef4444' : score <= 4 ? '#f59e0b' : '#22c55e';
  });

  registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideError();
    const submitBtn = document.getElementById('submitBtn');
    submitBtn.disabled = true;
    try {
      const res = await apiFetch('/auth/register', {
        method: 'POST',
        body: JSON.stringify({
          name: document.getElementById('name').value.trim(),
          email: document.getElementById('email').value.trim(),
          password: pwInput.value
        })
      }, false);
      await handleAuthResponse(res);
    } catch (err) {
      showError(err.message);
    } finally {
      submitBtn.disabled = false;
    }
  });
}

// ---- Google Sign-In ----
function initGoogleButton() {
  if (!window.google || !document.getElementById('googleBtn')) return;

  google.accounts.id.initialize({
    client_id: GOOGLE_CLIENT_ID,
    callback: async (response) => {
      hideError();
      try {
        const res = await apiFetch('/auth/google', {
          method: 'POST',
          body: JSON.stringify({ idToken: response.credential })
        }, false);
        await handleAuthResponse(res);
      } catch (err) {
        showError(err.message);
      }
    }
  });

  google.accounts.id.renderButton(document.getElementById('googleBtn'), {
    theme: 'outline',
    size: 'large',
    width: 356
  });
}

window.addEventListener('load', () => {
  // Google's script may still be loading; poll briefly.
  let attempts = 0;
  const timer = setInterval(() => {
    attempts++;
    if (window.google || attempts > 20) {
      clearInterval(timer);
      initGoogleButton();
    }
  }, 150);
});
