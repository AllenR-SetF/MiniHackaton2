'use strict';

/**
 * prjM3 — Password Hackathon API server.
 *
 * Built only with Node.js built-in modules (http, crypto). No auth/JWT libraries.
 *
 * Routes (all under BASE_PATH, default "/prjM3"):
 *   GET  {BASE}/api/health   -> liveness check (no auth)
 *   POST {BASE}/api/login    -> verify username/password, set JWT in HttpOnly cookie
 *   GET  {BASE}/api/me       -> verify JWT cookie, return team + secret
 *   POST {BASE}/api/logout   -> delete the cookie (JWT copies stay valid until exp)
 */

const http = require('http');
const crypto = require('crypto');
const { loadEnvFile } = require('./env');

loadEnvFile(); // reads backend/.env if it exists (never committed)

// ---------------------------------------------------------------------------
// Configuration (everything sensitive comes from environment variables)
// ---------------------------------------------------------------------------
const PORT = Number(process.env.PORT) || 3000;
const TEAM = process.env.TEAM || 'prjM3';
const BASE_PATH = (process.env.BASE_PATH ?? '/prjM3').replace(/\/+$/, '');
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'BCIT12';
const SECRET = process.env.SECRET || 'defaultSecret';
const FRONTEND_ORIGINS = (process.env.FRONTEND_ORIGIN || 'http://localhost:5500')
  .split(',')
  .map((s) => s.trim().replace(/\/+$/, ''))
  .filter(Boolean);
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const IS_PROD = process.env.NODE_ENV === 'production';

// JWT + cookie lifetime: 3 hours (rule: at least 2 hours).
const TOKEN_TTL_SECONDS = Number(process.env.TOKEN_TTL_SECONDS) || 3 * 60 * 60;
const COOKIE_NAME = 'token';

// The HMAC key for signing JWTs. MUST be stable across restarts, otherwise a
// restart would invalidate previously issued JWTs (violates rule 2).
let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  if (IS_PROD) {
    console.error('FATAL: JWT_SECRET must be set (>= 32 chars) in production.');
    process.exit(1);
  }
  JWT_SECRET = 'dev-only-insecure-jwt-secret-change-me-0123456789';
  console.warn('WARNING: using an insecure development JWT_SECRET.');
}

// Validate Phase 2 constraints so a typo during the 5-minute window is caught.
if (ADMIN_PASSWORD.length > 6) console.warn('WARNING: password longer than 6 chars (hackathon rule).');
if (SECRET.length >= 20 || /\s/.test(SECRET)) console.warn('WARNING: secret must be < 20 chars, no spaces.');

// ---------------------------------------------------------------------------
// Password hashing (scrypt, built into crypto). The plain password is hashed
// once at startup with a random salt; only the hash is kept around.
// ---------------------------------------------------------------------------
const PW_SALT = crypto.randomBytes(16);
const SCRYPT_OPTS = { N: 16384, r: 8, p: 1 };
const PW_HASH = crypto.scryptSync(ADMIN_PASSWORD, PW_SALT, 32, SCRYPT_OPTS);

function verifyPassword(candidate) {
  return new Promise((resolve) => {
    crypto.scrypt(String(candidate), PW_SALT, 32, SCRYPT_OPTS, (err, derived) => {
      if (err) return resolve(false);
      resolve(crypto.timingSafeEqual(derived, PW_HASH));
    });
  });
}

function safeEqualString(a, b) {
  // Compare via fixed-length digests so length differences don't leak timing.
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// "Credential version": a fingerprint of the current password + secret.
// Every JWT records the version it was issued under. Old JWTs remain VALID
// (they still authenticate and can open every page), but the secret is only
// revealed to JWTs issued under the current credentials. This stops teams who
// logged in with BCIT12 during Phase 1 from reading the new secret in Phase 3.
// Set REVEAL_SECRET_TO_OLD_TOKENS=1 to disable this defence.
const CRED_VERSION = crypto
  .createHmac('sha256', JWT_SECRET)
  .update(`${ADMIN_PASSWORD}\0${SECRET}`)
  .digest('base64url')
  .slice(0, 16);
const REVEAL_SECRET_TO_OLD_TOKENS = process.env.REVEAL_SECRET_TO_OLD_TOKENS === '1';

// ---------------------------------------------------------------------------
// Hand-written JWT (HS256)
// ---------------------------------------------------------------------------
const b64url = (input) => Buffer.from(input).toString('base64url');

function signJwt(payload) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const unsigned = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const signature = crypto.createHmac('sha256', JWT_SECRET).update(unsigned).digest('base64url');
  return `${unsigned}.${signature}`;
}

function verifyJwt(token) {
  if (typeof token !== 'string' || token.length > 2048) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;

  let header;
  let payload;
  try {
    header = JSON.parse(Buffer.from(h, 'base64url').toString('utf8'));
    payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  // Only accept exactly HS256 — blocks "alg: none" and algorithm-confusion attacks.
  if (!header || header.alg !== 'HS256' || header.typ !== 'JWT') return null;

  const expected = crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${p}`).digest();
  const given = Buffer.from(s, 'base64url');
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;

  const now = Math.floor(Date.now() / 1000);
  if (!payload || typeof payload.exp !== 'number' || payload.exp <= now) return null;
  if (payload.sub !== ADMIN_USERNAME) return null;
  return payload;
}

// ---------------------------------------------------------------------------
// Cookies
// ---------------------------------------------------------------------------
function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    const name = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (name && !(name in out)) {
      try { out[name] = decodeURIComponent(value); } catch { out[name] = value; }
    }
  }
  return out;
}

function buildCookie(value, maxAgeSeconds) {
  // SameSite=None + Secure is required because the client lives on a different
  // origin/site than this API. Partitioned (CHIPS) keeps it working in browsers
  // that block unpartitioned third-party cookies.
  const attrs = [
    `${COOKIE_NAME}=${value}`,
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=None',
    'Partitioned',
    `Max-Age=${maxAgeSeconds}`,
  ];
  if (maxAgeSeconds > 0) {
    attrs.push(`Expires=${new Date(Date.now() + maxAgeSeconds * 1000).toUTCString()}`);
  } else {
    attrs.push('Expires=Thu, 01 Jan 1970 00:00:00 GMT');
  }
  return attrs.join('; ');
}

// ---------------------------------------------------------------------------
// Rate limiting for login (brute-force defence). Checked BEFORE any hashing so
// a flood of guesses can't tie up CPU and slow the server down.
// ---------------------------------------------------------------------------
const PER_IP_MAX_FAILS = 20;         // per IP per window
const PER_IP_WINDOW_MS = 60 * 1000;
const GLOBAL_MAX_FAILS = 100;        // across all IPs per window (stops IP rotation)
const GLOBAL_WINDOW_MS = 60 * 1000;
const MAX_TRACKED_IPS = 10000;

const ipFails = new Map(); // ip -> { count, resetAt }
let globalFails = { count: 0, resetAt: Date.now() + GLOBAL_WINDOW_MS };

function clientIp(req) {
  if (TRUST_PROXY) {
    // X-Real-IP is set by the hosting proxy (Railway) and cannot be chosen by
    // the client. X-Forwarded-For is only a fallback: its first value is
    // whatever the client sent, so it can be faked.
    const real = req.headers['x-real-ip'];
    if (typeof real === 'string' && real.length) return real.trim();
    const xff = req.headers['x-forwarded-for'];
    if (typeof xff === 'string' && xff.length) return xff.split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

// A login attempt takes a slot BEFORE the slow password hash runs, and only a
// successful login gives the slot back. Counting failures afterwards would
// leave a gap: hundreds of guesses sent at the same instant would all pass the
// check before the first failure was recorded. It also caps how many hashes
// can run at once, so a burst cannot queue up CPU work and slow responses.
// Returns 0 if the attempt may proceed, otherwise seconds until retry.
function reserveAttempt(ip) {
  const now = Date.now();
  if (globalFails.resetAt <= now) globalFails = { count: 0, resetAt: now + GLOBAL_WINDOW_MS };

  let entry = ipFails.get(ip);
  if (!entry || entry.resetAt <= now) {
    if (!entry && ipFails.size >= MAX_TRACKED_IPS) ipFails.clear(); // bound memory
    entry = { count: 0, resetAt: now + PER_IP_WINDOW_MS };
    ipFails.set(ip, entry);
  }

  if (globalFails.count >= GLOBAL_MAX_FAILS) return Math.ceil((globalFails.resetAt - now) / 1000);
  if (entry.count >= PER_IP_MAX_FAILS) return Math.ceil((entry.resetAt - now) / 1000);

  globalFails.count += 1;
  entry.count += 1;
  return 0;
}

function refundAttempt(ip) {
  globalFails.count = Math.max(0, globalFails.count - 1);
  const entry = ipFails.get(ip);
  if (entry) entry.count = Math.max(0, entry.count - 1);
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, e] of ipFails) if (e.resetAt <= now) ipFails.delete(ip);
}, 60 * 1000).unref();

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------
const MAX_BODY_BYTES = 1024;

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(Object.assign(new Error('Payload too large'), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'));
      } catch {
        reject(Object.assign(new Error('Invalid JSON'), { status: 400 }));
      }
    });
    req.on('error', reject);
  });
}

function applyCors(req, res) {
  const origin = req.headers.origin;
  if (origin && FRONTEND_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Max-Age', '600');
  }
  res.setHeader('Vary', 'Origin');
}

function send(res, status, body, extraHeaders = {}) {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(data),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Strict-Transport-Security': 'max-age=31536000',
    ...extraHeaders,
  });
  res.end(data);
}

function originAllowed(req) {
  // Browser POSTs carry Origin; reject cross-site POSTs from unknown origins (CSRF).
  const origin = req.headers.origin;
  return !origin || FRONTEND_ORIGINS.includes(origin);
}

function authenticate(req) {
  const token = parseCookies(req.headers.cookie)[COOKIE_NAME];
  return verifyJwt(token);
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------
async function handleLogin(req, res) {
  if (!originAllowed(req)) return send(res, 403, { error: 'Forbidden origin' });

  const ip = clientIp(req);
  const retryAfter = reserveAttempt(ip); // takes a slot; kept unless login succeeds
  if (retryAfter) {
    return send(res, 429, { error: 'Too many failed attempts. Try again later.' }, {
      'Retry-After': String(retryAfter),
    });
  }

  let body;
  try {
    body = await readJsonBody(req);
  } catch (err) {
    return send(res, err.status || 400, { error: err.message });
  }

  const { username, password } = body || {};
  if (typeof username !== 'string' || typeof password !== 'string' || password.length > 64) {
    return send(res, 401, { error: 'Invalid username or password' });
  }

  // Always run the (slow) password check, even for a wrong username, so
  // response timing doesn't reveal which part was wrong.
  const userOk = safeEqualString(username, ADMIN_USERNAME);
  const passOk = await verifyPassword(password);

  if (!userOk || !passOk) {
    return send(res, 401, { error: 'Invalid username or password' });
  }
  refundAttempt(ip); // successful logins don't count against the limit

  const now = Math.floor(Date.now() / 1000);
  const token = signJwt({
    sub: ADMIN_USERNAME,
    team: TEAM,
    cv: CRED_VERSION,
    iat: now,
    exp: now + TOKEN_TTL_SECONDS,
    jti: crypto.randomBytes(8).toString('hex'),
  });

  return send(res, 200, { ok: true, team: TEAM }, {
    'Set-Cookie': buildCookie(token, TOKEN_TTL_SECONDS),
  });
}

function handleMe(req, res) {
  const payload = authenticate(req);
  if (!payload) return send(res, 401, { error: 'Not authenticated' });

  const current = payload.cv === CRED_VERSION;
  return send(res, 200, {
    user: payload.sub,
    team: TEAM,
    secret: current || REVEAL_SECRET_TO_OLD_TOKENS ? SECRET : null,
    stale: !current,
    exp: payload.exp,
  });
}

function handleLogout(req, res) {
  if (!originAllowed(req)) return send(res, 403, { error: 'Forbidden origin' });
  // Only deletes the browser cookie. The JWT itself stays valid until it expires.
  return send(res, 200, { ok: true }, { 'Set-Cookie': buildCookie('', 0) });
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  try {
    applyCors(req, res);

    const url = new URL(req.url, 'http://localhost');
    let path = url.pathname;

    if (BASE_PATH && (path === BASE_PATH || path.startsWith(`${BASE_PATH}/`))) {
      path = path.slice(BASE_PATH.length) || '/';
    } else if (BASE_PATH) {
      return send(res, 404, { error: 'Not found' });
    }

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      return res.end();
    }

    if (path === '/' || path === '/api/health') {
      if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, { error: 'Method not allowed' });
      return send(res, 200, { ok: true, team: TEAM });
    }
    if (path === '/api/login') {
      if (req.method !== 'POST') return send(res, 405, { error: 'Method not allowed' });
      return await handleLogin(req, res);
    }
    if (path === '/api/me') {
      if (req.method !== 'GET') return send(res, 405, { error: 'Method not allowed' });
      return handleMe(req, res);
    }
    if (path === '/api/logout') {
      if (req.method !== 'POST') return send(res, 405, { error: 'Method not allowed' });
      return handleLogout(req, res);
    }
    return send(res, 404, { error: 'Not found' });
  } catch (err) {
    console.error(err);
    if (!res.headersSent) send(res, 500, { error: 'Internal server error' });
    else res.destroy();
  }
});

// Slow-loris / hanging-connection protection: drop requests that take too long.
server.headersTimeout = 5000;
server.requestTimeout = 5000;
server.keepAliveTimeout = 5000;
server.maxHeadersCount = 50;

// Crash guards: a malformed request or an unexpected bug must never take the
// whole process down (an unreachable server counts as a defeat).
server.on('clientError', (err, socket) => {
  if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
  else socket.destroy();
});
process.on('uncaughtException', (err) => console.error('uncaughtException:', err));
process.on('unhandledRejection', (err) => console.error('unhandledRejection:', err));

server.listen(PORT, () => {
  console.log(`[${TEAM}] API listening on :${PORT}${BASE_PATH || ''}`);
  console.log(`Allowed frontend origin(s): ${FRONTEND_ORIGINS.join(', ')}`);
});

module.exports = { signJwt, verifyJwt, parseCookies };

// Claude AI was used in the development of this code
