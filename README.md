# Millionaire Tracking Habits

Full-stack routine & habit tracker: **one Node.js/Express server** that serves the frontend (`public/`) and the JSON API (`/api/*`), with a **SQLite** database (better-sqlite3), bcrypt passwords and a **JWT in an httpOnly cookie**.

> This is **not** a static site. It needs a host that runs Node.js **and** keeps a persistent disk for the SQLite file.

## Project structure
```
.
├─ server.js            Express API + static hosting + SPA fallback
├─ package.json         dependencies + "npm start"
├─ .env.example         every environment variable
├─ render.yaml          one-click Render blueprint (web service + persistent disk)
├─ netlify.toml         only for the optional split deployment
├─ .node-version        22
├─ scripts/write-config.js   writes public/config.js from API_URL (split deployment)
└─ public/
   ├─ index.html        the whole frontend (vanilla JS, hash routes)
   └─ config.js         runtime config: { API_URL: "" } (no secrets)
```

## Run locally
```bash
npm install
JWT_SECRET="any-long-random-string" npm start     # http://localhost:3000
```
Windows PowerShell: `$env:JWT_SECRET="any-long-random-string"; npm start`
Data is stored in `./data/habits.db` (created automatically, tables created on start). Password-reset links are printed in the terminal unless SMTP is configured.

## Environment variables
| Variable | Required | Purpose |
|---|---|---|
| `NODE_ENV=production` | prod | Secure cookies, HSTS, requires JWT_SECRET |
| `JWT_SECRET` | prod | >= 32 chars. `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"` |
| `DB_FILE` | prod | Absolute path **on a persistent disk**, e.g. `/var/data/habits.db` (default `./data/habits.db`) |
| `PORT` | auto | Set by the host; default 3000 |
| `APP_URL` | with SMTP | Public site URL used inside reset emails |
| `SMTP_HOST` `SMTP_PORT` `SMTP_USER` `SMTP_PASS` `SMTP_FROM` | optional | Sends real password-reset emails. Without them the reset link is only written to the server log |
| `CORS_ORIGIN` | split only | Comma-separated frontend origin(s). Enables CORS and `SameSite=None; Secure` cookies |
| `COOKIE_SAMESITE` | optional | `lax` / `strict` / `none` override |
| `TRUST_PROXY` | optional | Reverse-proxy hops (default 1 in production) |

## Deploy (recommended): one service on Render, same domain
Frontend and API share one origin, so cookies are first-party and the frontend uses relative `/api` URLs. No CORS needed.

1. Push this folder to a GitHub repo (`node_modules`, `data`, `.env` are git-ignored).
2. Render -> **New -> Blueprint** -> select the repo (uses `render.yaml`), or **New -> Web Service** with:
   - Build command `npm install` - Start command `npm start` - Health check path `/api/health`
   - **Disks -> Add disk**: mount path `/var/data`, 1 GB
   - Env vars: `NODE_ENV=production`, `JWT_SECRET=<generated>`, `DB_FILE=/var/data/habits.db`, `NODE_VERSION=22`
3. Deploy. Open `https://<your-service>.onrender.com/`.
4. (Real reset emails) add `APP_URL` + `SMTP_*`.

> **Persistence warning.** SQLite is a file. Hosts with an **ephemeral filesystem** wipe it on every deploy/restart: Render free instances (disks need a paid instance - check current pricing), Heroku, Railway/Fly **without a volume**, Netlify/Vercel/Cloudflare functions, most "free" tiers. Use a host with a persistent disk/volume (Render + disk, Railway + volume, Fly.io + volume, any VPS), or migrate to a hosted database (Postgres) - that is a code change, not config.

Same recipe works on a VPS: `npm install`, set the env vars, run `npm start` under systemd/pm2, put nginx/Caddy (HTTPS) in front.

## Optional: frontend on Netlify, backend elsewhere
Netlify **cannot** run this Express + SQLite server; uploading `index.html` alone gives a frontend with no API. If you still want Netlify for the frontend:
1. Deploy the backend as above (e.g. `https://habits-api.onrender.com`) and set there `CORS_ORIGIN=https://<your-site>.netlify.app` (cookie becomes `SameSite=None; Secure` automatically).
2. Netlify: connect the repo; `netlify.toml` already sets publish dir `public` and build command `node scripts/write-config.js`. Add env var `API_URL=https://habits-api.onrender.com`.
3. Open `https://<your-site>.netlify.app/`.

Caveat: `netlify.app` and `onrender.com` are different *sites*, so the login cookie is third-party. Safari, Brave and strict Chrome/Firefox settings block those, and users there cannot stay logged in. For a reliable split, use custom domains under one parent (`app.example.com` + `api.example.com`) and set `COOKIE_SAMESITE=lax` on the backend. The single-service deployment avoids all of this.

## URLs
- Frontend: `https://<host>/` - routes `/#/login`, `/#/signup`, `/#/dashboard`, `/#/routines`, `/#/calendar`, `/#/stats`, `/#/settings`, `/#/reset/<token>`
- API (same domain): `https://<host>/api/...` - health: `/api/health`
- API (split): `https://<api-host>/api/...`

## Security notes
bcrypt (cost 10) passwords - JWT (HS256, 30 days) only in an httpOnly cookie, secret never sent to the browser - `Secure` cookies in production - rate limits on signup/login/forgot/reset - JSON-only state-changing requests + Origin check (CSRF) - every query scoped by `user_id` - input validated server-side - reset tokens stored hashed, expire in 1 h.

## Test checklist (after deploy)
```bash
BASE=https://<host>                     # same-domain deployment
H='Content-Type: application/json'
curl -s $BASE/api/health                                        # {"ok":true}
curl -s -c jar -H "$H" -d '{"name":"Test","email":"t@example.com","password":"password123"}' $BASE/api/signup
curl -s -b jar $BASE/api/me                                     # user JSON (session cookie works)
curl -s -b jar -H "$H" -d '{"name":"Run","category":"Fitness","days":[0,1,2,3,4,5,6],"start_date":"2026-10-01"}' $BASE/api/routines   # {"id":1}
curl -s -b jar $BASE/api/day/2026-10-07                         # contains "Run", status null
curl -s -b jar -X PUT -H "$H" -d '{"routine_id":1,"date":"2026-10-07","status":1}' $BASE/api/track
curl -s -b jar "$BASE/api/stats?today=2026-10-07"               # done:1
curl -s -b jar $BASE/api/month/2026-10                          # day 2026-10-07 done:1
curl -s -o /dev/null -w "%{http_code}\n" $BASE/api/me           # 401 without cookie
```
Then in the browser: signup -> refresh (still logged in) -> add / edit / duplicate / reorder / pause / delete routine -> tick and untick -> calendar -> statistics -> settings -> change password -> logout -> log in with the new password -> forgot password (link in server log or email) -> reset.
**Persistence proof:** after creating data, trigger a redeploy/restart in the host dashboard and log in again - your routines must still be there. If they vanish, the disk is not persistent / `DB_FILE` is not on it.
