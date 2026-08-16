# Secure Login System

A self-contained Node.js/Express login app with hashed passwords, input
validation, SQL-injection-safe queries, session management, CSRF
protection, brute-force lockout, and optional TOTP-based 2FA. Uses SQLite
so there's no external database to install.

## Setup

```bash
npm install
cp .env.example .env
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
# paste the output into SESSION_SECRET in .env
npm start
```

Visit `http://localhost:3000`. The SQLite database files are created
automatically in `db/` on first run.

## Security features and where they live

| Feature | Implementation |
|---|---|
| Password hashing | `bcryptjs`, cost factor 12 (`src/routes/authRoutes.js`) |
| SQL injection protection | All queries use `better-sqlite3` prepared statements with bound parameters, never string concatenation (`src/db/users.js`) |
| Input validation | `express-validator` rules for username/email/password format (`src/routes/authRoutes.js`) |
| XSS protection | EJS auto-escapes all output by default; `helmet` sets a restrictive Content-Security-Policy |
| CSRF protection | Per-session random token verified on every state-changing POST (`src/middleware/auth.js`) |
| Session management | `express-session` with SQLite-backed store, `httpOnly`/`sameSite` cookies, session ID regenerated on login to prevent fixation |
| Brute-force protection | Per-IP rate limiting (`express-rate-limit`) + per-account lockout after 5 failed attempts for 15 minutes |
| Username enumeration resistance | Identical error message and near-identical response timing for "no such user" vs "wrong password" |
| Optional 2FA | TOTP (RFC 6238) via `speakeasy`, QR provisioning via `qrcode` — compatible with Google Authenticator, Authy, 1Password, etc. |

## Login flow

1. `POST /register` — creates the account with a bcrypt hash of the password; the plaintext password is never stored.
2. `POST /login` — verifies the password. If 2FA is **not** enabled, the session is established immediately. If it **is** enabled, the app stores a temporary `pendingUserId` and redirects to `/login/2fa` — the session is only fully authenticated after the TOTP code checks out.
3. `POST /logout` — destroys the server-side session and clears the cookie.

## Notes for production deployment

- Set `NODE_ENV=production` so cookies are marked `secure` (HTTPS only) — you must actually serve over HTTPS (e.g. behind nginx or a platform load balancer with TLS) for this to work correctly.
- Put the app behind a reverse proxy and set `app.set('trust proxy', 1)` if you rely on rate-limiting by real client IP.
- Consider adding email verification and a "forgot password" flow (not included here) before going live.
- Back up `db/app.db` regularly; it's the only copy of your user data.
