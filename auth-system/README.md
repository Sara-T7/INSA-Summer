# Authentication System (Node/Express + MySQL/XAMPP + HTML/CSS/JS)

Covers every requirement:

| Requirement | How it's handled |
|---|---|
| No weak passwords | Server + client-side rules: 8+ chars, upper/lower/number/symbol, blocks common passwords (`utils/validators.js`) |
| Prevent brute-force | Per-IP rate limiting on `/login` + per-account lockout after 5 failed attempts (15 min) (`middleware/rateLimiter.js`, `auth.controller.js`) |
| Stay logged in without long-lived access tokens | Short-lived JWT access token (15 min) + rotating opaque refresh token in an `httpOnly` cookie (`utils/tokens.js`) |
| Sign in with Google | Google Identity Services on the frontend, `google-auth-library` verifies the ID token on the backend (`auth.controller.js` → `googleLogin`) |
| Detect suspicious logins | Each session records IP + user-agent; a login from a combination never seen before for that user is flagged `is_suspicious` and shown on the dashboard |
| View/manage active sessions | `GET /api/sessions` and `DELETE /api/sessions/:id`, rendered as a table with a Revoke button (`dashboard.html`) |

## 1. Database (XAMPP / MySQL)

1. Start MySQL from the XAMPP control panel.
2. Open phpMyAdmin (or a MySQL client) and run `backend/db/schema.sql`.
   This creates the `auth_system` database with `users`, `sessions`, and `login_attempts` tables.

## 2. Backend

```bash
cd backend
npm install
cp .env.example .env
```

Edit `.env`:
- `DB_USER` / `DB_PASSWORD` — your XAMPP MySQL credentials (default XAMPP is user `root`, empty password).
- `JWT_ACCESS_SECRET` — generate one with `node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"`.
- `GOOGLE_CLIENT_ID` — from https://console.cloud.google.com/apis/credentials (OAuth Client ID → Web application). Add `http://localhost:5500` (or wherever you serve the frontend) to **Authorized JavaScript origins**.
- `CORS_ORIGIN` — the URL where you serve the frontend files.

Run it:

```bash
npm start
```

Server runs on `http://localhost:4000`.

## 3. Frontend

The frontend is plain HTML/CSS/JS — no build step. Serve it with any static server so cookies work correctly, e.g.:

```bash
cd frontend
npx serve -l 5500
```

Then edit `frontend/js/config.js` and set `GOOGLE_CLIENT_ID` to match your `.env`.

Open `http://localhost:5500` in your browser.

## Notes on the design

- **Access vs refresh tokens**: the access token is a JWT that protected routes verify statelessly (`middleware/auth.middleware.js`). It expires in 15 minutes. The refresh token is a random 96-character string; only its SHA-256 hash is ever stored in MySQL, and the raw value lives in an `httpOnly`, `SameSite=Lax` cookie the JS can't read. Every refresh **rotates** the token (old one is revoked, a new one issued), so a stolen refresh token stops working the next time the real user refreshes.
- **Passwords** are hashed with bcrypt (12 rounds), never stored or logged in plain text.
- **Brute-force protection** is two layers: an IP-based rate limit (stops spraying many accounts from one IP) and a per-account lockout counter (stops many guesses against one account from many IPs).
- **Suspicious login detection** here is intentionally simple (new IP+device combo) so it runs with zero external services. You could extend it with a geo-IP lookup service or email alerts.
- **Password reset / email verification** aren't in the requirements list above, so they're not included, but the schema and structure make them straightforward to add later (a `password_resets` table + a `/forgot-password` route, following the same pattern as the rest of the code).
