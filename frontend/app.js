'use strict';

// Shared client logic. The JWT lives in an HttpOnly cookie, so this script can
// never read it — it just asks the API "who am I?" and lets the browser attach
// the cookie (credentials: 'include').

const { TEAM, API_BASE } = window.APP_CONFIG;

async function api(path, options = {}) {
  const res = await fetch(API_BASE + path, {
    credentials: 'include', // send/receive the cross-origin HttpOnly cookie
    cache: 'no-store',
    ...options,
    headers: options.body ? { 'Content-Type': 'application/json' } : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch { /* empty body */ }
  return { ok: res.ok, status: res.status, data };
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text; // textContent, never innerHTML (no XSS)
}

document.querySelectorAll('[data-team]').forEach((el) => { el.textContent = TEAM; });

// ---- Login page -----------------------------------------------------------
async function initLogin() {
  // Already logged in? Go straight to the landing page.
  try {
    const me = await api('/api/me');
    if (me.ok) return location.replace('admin.html');
  } catch { /* API unreachable: show the form anyway */ }

  const form = document.getElementById('login-form');
  const button = document.getElementById('login-button');

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    setText('error', '');
    button.disabled = true;
    try {
      const result = await api('/api/login', {
        method: 'POST',
        body: JSON.stringify({
          username: form.username.value,
          password: form.password.value,
        }),
      });
      if (result.ok) return location.replace('admin.html');
      setText('error', (result.data && result.data.error) || `Login failed (${result.status})`);
    } catch {
      setText('error', 'Could not reach the server. Please try again.');
    } finally {
      button.disabled = false;
    }
  });
}

// ---- Protected pages ------------------------------------------------------
async function initProtected() {
  let me;
  try {
    me = await api('/api/me');
  } catch {
    me = { ok: false };
  }
  if (!me.ok) return location.replace('index.html'); // unauthenticated -> Login

  const logout = document.getElementById('logout');
  logout.addEventListener('click', async (event) => {
    event.preventDefault();
    try { await api('/api/logout', { method: 'POST' }); } catch { /* ignore */ }
    location.replace('index.html');
  });

  const welcome = document.getElementById('welcome');
  if (welcome) {
    const secret = me.data.secret === null
      ? '[hidden: this session predates a credential change — log in again]'
      : `"${me.data.secret}"`;
    const render = () => {
      // Time is the BROWSER's current date and time.
      welcome.textContent =
        `Welcome to Team ${me.data.team}, Secret: ${secret}, Time: ${new Date().toLocaleString()}`;
    };
    render();
    setInterval(render, 1000);
  }

  document.body.hidden = false; // reveal only after auth succeeded
}

if (document.body.dataset.page === 'login') initLogin();
else initProtected();
