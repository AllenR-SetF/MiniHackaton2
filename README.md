# prjM3 — Password Hackathon (COMP 4537)

JWT authentication in an HttpOnly cookie, written by hand with Node.js built-ins
(`http`, `crypto`). No npm dependencies at all.

```
frontend/   static client (HTML/CSS/JS)            -> origin A (static host)
backend/    Node.js API (server.js, env.js)         -> origin B (Node host)
```

## Run locally

Two terminals, two origins (`localhost:5500` client, `localhost:3000` API):

```bash
node backend/server.js
```

```bash
node frontend/dev-server.js
```

Open http://localhost:5500 and log in with `admin` / `BCIT12`.

## How it works (know this for the verbal check)

**Login** — `POST /prjM3/api/login` with JSON `{username, password}`.
The server checks the rate limiter, then compares the password using `crypto.scrypt`
(hash computed at startup with a random salt) and `crypto.timingSafeEqual`.
On success it builds a JWT and sends it in `Set-Cookie`.

**JWT** — `base64url(header) + "." + base64url(payload) + "." + signature`, where
`signature = HMAC-SHA256(JWT_SECRET, header.payload)`. Payload: `sub`, `team`, `cv`,
`iat`, `exp` (3 h), `jti`. Verification recomputes the HMAC, compares in constant
time, requires `alg` to be exactly `HS256`, and checks `exp`.

**Cookie** — `HttpOnly` (JavaScript cannot read it, so XSS cannot steal it),
`Secure` (HTTPS only), `SameSite=None` (required because client and API are on
different sites), `Partitioned` (works where third-party cookies are restricted),
`Max-Age=10800` (3 h).

**Cross-origin** — the client calls the API with `fetch(..., {credentials: 'include'})`.
The API answers with `Access-Control-Allow-Origin: <exact frontend origin>` and
`Access-Control-Allow-Credentials: true` (a `*` wildcard is not allowed with credentials).

**Protected pages** — every page calls `GET /prjM3/api/me` on load. `401` → redirect
to Login. The page body stays hidden until that check passes. The secret is never in
the frontend files; it only comes from `/api/me`. The time shown is the browser's
(`new Date()`).

**Logout** — `POST /prjM3/api/logout` overwrites the cookie with `Max-Age=0`. There is
no server-side session or blocklist, so a copied JWT stays valid until `exp` (rule 2).

## Defences

| Attack | Defence |
| --- | --- |
| Brute-forcing the 6-char password | 5 failed logins/min per IP **and** 30/min globally (IP rotation doesn't help) → `429`. Checked before hashing. |
| Reusing a Phase 1 JWT to read the new secret | Each JWT carries `cv`, an HMAC fingerprint of the password + secret at issue time. Old JWTs still authenticate and open every page, but `/api/me` returns `secret: null` unless `cv` matches the current credentials. |
| Forged JWT (`alg: none`, tampered payload, guessed key) | Strict `HS256` check, constant-time HMAC compare, 48-byte random `JWT_SECRET` from env. |
| Timing attacks | `timingSafeEqual` everywhere; password check always runs, even for a wrong username. |
| Slow response / DoS | No database, no dependencies, 1 KB body limit, 5 s header/request timeouts (slow-loris), rate limit before CPU work, bounded limiter memory. |
| CSRF / rogue origins | CORS allow-list of the exact frontend origin; POSTs with a foreign `Origin` → `403`. |
| XSS | Output via `textContent` only; cookie is HttpOnly. |
| Secret leaking through the repo/ZIP | Password, secret and JWT key live only in host environment variables (`.env` is git-ignored). |

> **Rule-interpretation note:** hiding the secret from pre-change JWTs keeps those JWTs
> valid (rule 2) but is a judgment call. If the instructor says old JWTs must also see
> the new secret, set `REVEAL_SECRET_TO_OLD_TOKENS=1`. Ask before the hackathon.

## Deploy (two HTTPS origins, team number in both URLs)

**Backend** → any Node host (Render, Railway, Fly.io…). Root directory `backend`,
start command `node server.js`, no build step. Environment variables — see
[backend/.env.example](backend/.env.example):

- `NODE_ENV=production`, `TRUST_PROXY=1`
- `JWT_SECRET` — generate once with `npm run gen-jwt-secret` (in `backend/`); never change it mid-hackathon
- `FRONTEND_ORIGIN` — e.g. `https://YOUR-USER.github.io` (origin only, no path, no trailing slash)
- `ADMIN_PASSWORD=BCIT12`, `SECRET=defaultSecret`

API URL: `https://<host>/prjM3/api/...` (the `/prjM3` path prefix guarantees the team
number is in the URL whatever the hostname is).

**Frontend** → any static host. Simplest: GitHub Pages from a repo named `prjM3`,
giving `https://YOUR-USER.github.io/prjM3/`. First edit
[frontend/config.js](frontend/config.js) and set `API_BASE` to the deployed API URL.

**Warning — free tiers that sleep** (e.g. Render free) take 30+ s to wake up. A
response over 5 s counts as a defeat, and a slow app at verification is a 0. Use an
always-on instance for the lecture.

## Phase 2 checklist (5 minutes, one restart)

1. On the backend host, change `ADMIN_PASSWORD` (max 6 chars — use random mixed
   case + digits + symbols, e.g. not a word) and `SECRET` (< 20 chars, no spaces).
   Do **not** touch `JWT_SECRET`.
2. Save → the host restarts the service once.
3. Log in with the new password, confirm the new secret shows.
4. Post the `READY — prjM3, Set …` message.

## Submission

Zip `frontend/` and `backend/` as `prjM3_passwordHackathon.zip` and post both HTTPS
links in Learning Hub.
