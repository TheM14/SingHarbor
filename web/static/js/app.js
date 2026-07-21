/* SingHarbor WebUI API Client */

class SingHarborAPI {
  constructor() {
    this.csrfToken = '';
  }

  async request(method, url, body) {
    const headers = {'Content-Type': 'application/json'};
    if (this.csrfToken) {
      headers['X-CSRF-Token'] = this.csrfToken;
    }
    const opts = {method, headers};
    if (body) opts.body = JSON.stringify(body);

    const resp = await fetch(url, opts);
    const contentType = resp.headers.get('content-type') || '';
    const data = contentType.includes('application/json') ? await resp.json() : {};
    if (data.csrf_token) {
      this.csrfToken = data.csrf_token;
    }
    if (!resp.ok) {
      const error = new Error(data.error || `Request failed (${resp.status})`);
      error.status = resp.status;
      error.data = data;
      throw error;
    }
    return data;
  }

  get(url) { return this.request('GET', url); }
  post(url, body) { return this.request('POST', url, body); }
  put(url, body) { return this.request('PUT', url, body); }
  del(url) { return this.request('DELETE', url); }

  flash(message) {
    const existing = document.querySelector('.toast');
    if (existing) existing.remove();
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = message;
    toast.style.cursor = 'pointer';
    toast.title = 'Click to dismiss';
    toast.addEventListener('click', () => toast.remove());
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
  }
}

/* ---- Utility functions ---- */

function escHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function escAttr(str) {
  return escHtml(str);
}

function escJs(str) {
  return String(str || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '\\"');
}

function setLoading(btn, label) {
  btn.disabled = true;
  btn._originalText = btn.textContent;
  btn.textContent = label || 'Loading...';
}

function resetLoading(btn) {
  btn.disabled = false;
  if (btn._originalText) {
    btn.textContent = btn._originalText;
    delete btn._originalText;
  }
}

/* ---- Shell and theme ---- */

function resolveTheme(choice) {
  if (choice === 'system') {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  return choice === 'dark' ? 'dark' : 'light';
}

function applyTheme(choice) {
  const safeChoice = ['light', 'dark', 'system'].includes(choice) ? choice : 'light';
  localStorage.setItem('sh_theme', safeChoice);
  document.documentElement.dataset.themeChoice = safeChoice;
  document.documentElement.dataset.theme = resolveTheme(safeChoice);
  const toggle = document.getElementById('theme-toggle');
  if (toggle) {
    const dark = document.documentElement.dataset.theme === 'dark';
    toggle.textContent = dark ? '☀' : '☾';
    toggle.setAttribute('aria-pressed', dark ? 'true' : 'false');
  }
  const select = document.getElementById('theme-select');
  if (select) select.value = safeChoice;
}

function initShell() {
  applyTheme(document.documentElement.dataset.themeChoice || 'light');
  const themeToggle = document.getElementById('theme-toggle');
  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
    });
  }
  const navToggle = document.getElementById('nav-toggle');
  const nav = document.getElementById('main-nav');
  if (navToggle && nav) {
    navToggle.addEventListener('click', () => {
      const open = nav.classList.toggle('is-open');
      navToggle.setAttribute('aria-expanded', String(open));
    });
  }
  const logoutButton = document.getElementById('logout-btn');
  if (logoutButton) logoutButton.addEventListener('click', logout);
  document.querySelectorAll('.lang-link').forEach((link) => {
    link.addEventListener('click', (event) => {
      event.preventDefault();
      setLang(link.dataset.lang);
    });
  });
  const media = window.matchMedia('(prefers-color-scheme: dark)');
  if (media.addEventListener) {
    media.addEventListener('change', () => {
      if ((localStorage.getItem('sh_theme') || 'light') === 'system') applyTheme('system');
    });
  }
}

/* ---- Auth initialization ---- */

const API = new SingHarborAPI();

async function initAuth() {
  try {
    const resp = await fetch('/auth/status');
    const data = await resp.json();

    if (!data.initialized) {
      if (window.location.pathname !== '/setup') {
        window.location.href = '/setup';
      }
      return;
    }

    if (!data.authenticated && data.initialized) {
      if (window.location.pathname !== '/login') {
        window.location.href = '/login';
      }
      return;
    }

    if (data.authenticated) {
      document.getElementById('main-nav').hidden = false;
      document.getElementById('nav-toggle').hidden = false;
      if (data.csrf_token) {
        API.csrfToken = data.csrf_token;
      }
      if (window.location.pathname === '/login' || window.location.pathname === '/setup') {
        window.location.href = '/dashboard';
      }
    }
  } catch (e) {
    console.error('Auth check failed:', e);
  }
}

async function logout() {
  try {
    await API.post('/auth/logout', {});
  } catch (e) {}
  window.location.href = '/login';
}

function confirmAction(message) {
  return window.confirm(message);
}

async function setLang(lang) {
  await fetch('/api/settings/lang', {
    method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-CSRF-Token': API.csrfToken},
    body: JSON.stringify({lang: lang}),
  });
  window.location.reload();
}
