'use strict';
/**
 * Millionaire Tracking Habits — Express + SQLite (better-sqlite3)
 * Serves the frontend from /public AND the JSON API under /api.
 */
const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const rateLimitLib = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
let nodemailer = null;
try { nodemailer = require('nodemailer'); } catch { /* optional: only needed for reset emails */ }

const rateLimit = rateLimitLib.rateLimit || rateLimitLib;
const env = process.env;
const PROD = env.NODE_ENV === 'production';
const PORT = Number(env.PORT) || 3000;
const fatal = (m) => { console.error('FATAL: ' + m); process.exit(1); };

/* ------------------------------------------------------------------ config */
if (PROD && !env.JWT_SECRET) fatal('JWT_SECRET environment variable is required in production.');
if (PROD && env.JWT_SECRET.length < 32) {
  fatal('JWT_SECRET must be at least 32 characters. Generate one with: node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'hex\'))"');
}
if (!env.JWT_SECRET) console.warn('[warn] JWT_SECRET not set - using an insecure development-only secret.');
const SECRET = env.JWT_SECRET || 'dev-only-secret-change-me';

const list = (v) => String(v || '').split(',').map((s) => s.trim().replace(/\/+$/, '')).filter(Boolean);
// Origins allowed to call the API from a DIFFERENT domain (leave empty when frontend + API share a domain).
const CORS_ORIGINS = list(env.CORS_ORIGIN);
const CROSS_SITE = CORS_ORIGINS.length > 0;
const SAMESITE = String(env.COOKIE_SAMESITE || (CROSS_SITE ? 'none' : 'lax')).toLowerCase();
if (!['lax', 'strict', 'none'].includes(SAMESITE)) fatal('COOKIE_SAMESITE must be lax, strict or none.');
// SameSite=None is rejected by browsers unless Secure is also set.
const COOKIE = { httpOnly: true, secure: PROD || SAMESITE === 'none', sameSite: SAMESITE, path: '/' };
const COOKIE_MAX_AGE = 30 * 24 * 3600 * 1000;
const API_ORIGIN = String(env.PUBLIC_API_URL || '').trim().replace(/\/+$/, '');
const APP_URL = String(env.APP_URL || '').trim().replace(/\/+$/, '');

const SMTP = (env.SMTP_HOST && nodemailer)
  ? nodemailer.createTransport({
      host: env.SMTP_HOST,
      port: Number(env.SMTP_PORT) || 587,
      secure: Number(env.SMTP_PORT) === 465,
      auth: env.SMTP_USER ? { user: env.SMTP_USER, pass: env.SMTP_PASS } : undefined,
    })
  : null;
if (PROD && SMTP && !APP_URL) fatal('APP_URL (the public URL of the site) is required when SMTP is configured.');
if (PROD && !SMTP) console.warn('[warn] SMTP is not configured: password-reset links are written to the server log instead of being emailed.');

/* ---------------------------------------------------------------- database */
const DB_FILE = path.resolve(env.DB_FILE || path.join(__dirname, 'data', 'habits.db'));
try { fs.mkdirSync(path.dirname(DB_FILE), { recursive: true }); }
catch (e) { fatal(`Cannot create the database folder ${path.dirname(DB_FILE)}: ${e.message}. Is the persistent disk/volume mounted?`); }
let db;
try { db = new Database(DB_FILE); }
catch (e) { fatal(`Cannot open the SQLite database at ${DB_FILE}: ${e.message}`); }
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,password TEXT NOT NULL,settings TEXT DEFAULT '{}',reset_token TEXT,reset_exp INTEGER,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS categories(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,name TEXT NOT NULL,UNIQUE(user_id,name));
CREATE TABLE IF NOT EXISTS routines(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,name TEXT NOT NULL,description TEXT,category TEXT,start_time TEXT,end_time TEXT,priority TEXT DEFAULT 'medium',days TEXT NOT NULL,start_date TEXT NOT NULL,end_date TEXT,reminder INTEGER DEFAULT 0,active INTEGER DEFAULT 1,sort INTEGER DEFAULT 0,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS tracking(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,routine_id INTEGER NOT NULL REFERENCES routines(id) ON DELETE CASCADE,date TEXT NOT NULL,status INTEGER NOT NULL,completed_at TEXT,UNIQUE(routine_id,date));
CREATE INDEX IF NOT EXISTS ix_t ON tracking(user_id,date);
CREATE INDEX IF NOT EXISTS ix_r ON routines(user_id,sort);
`);

const DEFAULT_CATEGORIES = ['Health', 'Fitness', 'Study', 'Work', 'Personal', 'Reading', 'Skills', 'Other'];
const DEFAULT_SETTINGS = { min_pct: 100, week_start: 0, time12: true, theme: 'system', notify: false };
const DUMMY_HASH = bcrypt.hashSync('timing-equaliser', 10); // keeps login timing equal for unknown emails

/* --------------------------------------------------------------------- app */
const PUBLIC_DIR = path.join(__dirname, 'public');
const app = express();
app.disable('x-powered-by');
// Behind a hosting proxy (Render, Railway, Fly, Heroku...) the real client IP / https come from X-Forwarded-*.
const tp = env.TRUST_PROXY;
app.set('trust proxy', tp === undefined ? (PROD ? 1 : false) : /^\d+$/.test(tp) ? Number(tp) : tp === 'true' ? true : tp === 'false' ? false : tp);

app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'same-origin',
    'Content-Security-Policy': `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ${API_ORIGIN}; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`,
  });
  if (PROD) res.set('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
  next();
});

// Runtime config for the frontend (contains NO secrets). Empty API_URL = same-origin relative /api calls.
app.get('/config.js', (req, res) => {
  res.type('application/javascript').set('Cache-Control', 'no-store')
    .send('window.APP_CONFIG=' + JSON.stringify({ API_URL: API_ORIGIN }).replace(/</g, '\\u003c') + ';');
});

// CORS (only when CORS_ORIGIN is set) + CSRF guard for state-changing requests.
app.use('/api', (req, res, next) => {
  const origin = req.get('origin');
  const allowed = !!origin && CORS_ORIGINS.includes(origin.replace(/\/+$/, ''));
  if (allowed) {
    res.set({ 'Access-Control-Allow-Origin': origin, 'Access-Control-Allow-Credentials': 'true' });
    res.vary('Origin');
  }
  if (req.method === 'OPTIONS') {
    if (allowed) {
      res.set({ 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Max-Age': '600' });
      return res.sendStatus(204);
    }
    return res.sendStatus(origin ? 403 : 204);
  }
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    let sameHost = false;
    try { sameHost = !!origin && new URL(origin).host === req.get('host'); } catch { /* bad Origin header */ }
    if (origin && !allowed && !sameHost) return res.status(403).json({ error: 'Origin not allowed.' });
    if (!/^application\/json\b/i.test(req.get('content-type') || '')) return res.status(415).json({ error: 'Content-Type must be application/json.' });
  }
  next();
});

app.use(express.json({ limit: '50kb' }), cookieParser());

app.use(express.static(PUBLIC_DIR, {
  maxAge: PROD ? '1h' : 0,
  setHeaders: (res, file) => { if (file.endsWith('.html')) res.set('Cache-Control', 'no-cache'); },
}));

/* ----------------------------------------------------------------- helpers */
const bad = (message, status) => { const e = new Error(message); e.v = true; e.status = status || 400; throw e; };
const h = (fn) => (req, res, next) => { try { fn(req, res, next); } catch (e) { next(e); } }; // sync handler -> central error handler
const str = (v, n) => String(v ?? '').trim().slice(0, n);
const isDate = (v) => typeof v === 'string' && /^\d{4}-\d\d-\d\d$/.test(v) && !Number.isNaN(Date.parse(v + 'T00:00:00Z')) && new Date(v + 'T00:00:00Z').toISOString().slice(0, 10) === v;
const chkDate = (v) => (isDate(v) ? v : bad('Invalid date'));
const rid = (v) => { const n = Number(v); return Number.isInteger(n) && n > 0 ? n : bad('Invalid id'); };
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;
const checkPassword = (p) => (typeof p === 'string' && p.length >= 8 && p.length <= 100 ? p : bad('Password must be 8-100 characters'));

function getUser(id) {
  const u = db.prepare('SELECT id,name,email,settings FROM users WHERE id=?').get(id);
  if (!u) bad('Please log in.', 401);
  let s = {};
  try { s = JSON.parse(u.settings || '{}'); } catch { /* corrupt settings -> defaults */ }
  return { user: { id: u.id, name: u.name, email: u.email }, settings: { ...DEFAULT_SETTINGS, ...s } };
}
const setCookie = (res, id) => res.cookie('t', jwt.sign({ id }, SECRET, { expiresIn: '30d', algorithm: 'HS256' }), { ...COOKIE, maxAge: COOKIE_MAX_AGE });

function auth(req, res, next) {
  let id;
  try { id = jwt.verify(req.cookies && req.cookies.t, SECRET, { algorithms: ['HS256'] }).id; }
  catch { return res.status(401).json({ error: 'Please log in.' }); }
  try {
    if (!db.prepare('SELECT 1 FROM users WHERE id=?').get(id)) return res.status(401).json({ error: 'Please log in.' });
    req.uid = id;
    next();
  } catch (e) { next(e); } // real DB failures are NOT disguised as 401
}

const limiter = (windowMs, limit, message, extra) => rateLimit({
  windowMs, limit, standardHeaders: true, legacyHeaders: false, ...extra,
  handler: (req, res) => res.status(429).json({ error: message }),
});
const authLimiter = limiter(15 * 60 * 1000, 20, 'Too many attempts. Please wait 15 minutes and try again.');
const loginLimiter = limiter(15 * 60 * 1000, 10, 'Too many login attempts. Please wait 15 minutes and try again.', { skipSuccessfulRequests: true });
const resetLimiter = limiter(60 * 60 * 1000, 5, 'Too many reset requests. Please try again in an hour.');
app.use('/api', limiter(15 * 60 * 1000, 1500, 'Too many requests. Please slow down.'));

/* -------------------------------------------------------------- auth routes */
app.get('/api/health', h((req, res) => { db.prepare('SELECT 1').get(); res.json({ ok: true }); }));

app.post('/api/signup', authLimiter, h((req, res) => {
  const name = str(req.body.name, 60), email = str(req.body.email, 320).toLowerCase();
  if (!name) bad('Name is required');
  if (!EMAIL_RE.test(email)) bad('Enter a valid email');
  checkPassword(req.body.password);
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) bad('That email is already registered', 409);
  const id = db.prepare('INSERT INTO users(name,email,password) VALUES(?,?,?)').run(name, email, bcrypt.hashSync(req.body.password, 10)).lastInsertRowid;
  setCookie(res, id);
  res.json(getUser(id));
}));

app.post('/api/login', loginLimiter, h((req, res) => {
  const u = db.prepare('SELECT id,password FROM users WHERE email=?').get(str(req.body.email, 320).toLowerCase());
  const pass = typeof req.body.password === 'string' ? req.body.password : '';
  const ok = bcrypt.compareSync(pass, u ? u.password : DUMMY_HASH);
  if (!u || !ok) bad('Invalid email or password', 401);
  setCookie(res, u.id);
  res.json(getUser(u.id));
}));

app.post('/api/logout', (req, res) => { res.clearCookie('t', COOKIE); res.json({ ok: 1 }); });

app.post('/api/forgot', resetLimiter, h((req, res) => {
  const email = str(req.body.email, 320).toLowerCase();
  const u = db.prepare('SELECT id FROM users WHERE email=?').get(email);
  if (u) {
    const token = crypto.randomBytes(24).toString('hex');
    db.prepare('UPDATE users SET reset_token=?,reset_exp=? WHERE id=?').run(crypto.createHash('sha256').update(token).digest('hex'), Date.now() + 36e5, u.id);
    const base = APP_URL || `${req.protocol}://${req.get('host')}`;
    sendResetLink(email, `${base}/#/reset/${token}`);
  }
  res.json({ ok: 1 }); // same answer whether or not the email exists
}));

function sendResetLink(email, link) {
  if (!SMTP) { console.log(`[password reset] SMTP not configured. Reset link for ${email}: ${link}`); return; }
  SMTP.sendMail({
    from: env.SMTP_FROM || env.SMTP_USER, to: email,
    subject: 'Reset your Millionaire Tracking Habits password',
    text: `Use this link within 1 hour to choose a new password:\n\n${link}\n\nIf you did not request this, you can ignore this email.`,
  }).catch((e) => console.error('[password reset] email failed:', e.message));
}

app.post('/api/reset', resetLimiter, h((req, res) => {
  checkPassword(req.body.password);
  if (typeof req.body.token !== 'string' || !/^[a-f0-9]{48}$/.test(req.body.token)) bad('This reset link is invalid or has expired');
  const hash = crypto.createHash('sha256').update(req.body.token).digest('hex');
  const u = db.prepare('SELECT id FROM users WHERE reset_token=? AND reset_exp>?').get(hash, Date.now());
  if (!u) bad('This reset link is invalid or has expired');
  db.prepare('UPDATE users SET password=?,reset_token=NULL,reset_exp=NULL WHERE id=?').run(bcrypt.hashSync(req.body.password, 10), u.id);
  res.json({ ok: 1 });
}));

app.get('/api/me', auth, h((req, res) => res.json(getUser(req.uid))));

app.put('/api/me', auth, h((req, res) => {
  const name = str(req.body.name, 60), email = str(req.body.email, 320).toLowerCase();
  const s = req.body.settings && typeof req.body.settings === 'object' ? req.body.settings : {};
  if (!name) bad('Name is required');
  if (!EMAIL_RE.test(email)) bad('Enter a valid email');
  if (db.prepare('SELECT id FROM users WHERE email=? AND id!=?').get(email, req.uid)) bad('That email is already in use', 409);
  const st = {
    min_pct: Math.min(100, Math.max(1, Math.round(+s.min_pct) || 100)),
    week_start: s.week_start == 1 ? 1 : 0,
    time12: !!s.time12,
    theme: ['light', 'dark', 'system'].includes(s.theme) ? s.theme : 'system',
    notify: !!s.notify,
  };
  db.prepare('UPDATE users SET name=?,email=?,settings=? WHERE id=?').run(name, email, JSON.stringify(st), req.uid);
  res.json(getUser(req.uid));
}));

app.put('/api/password', auth, h((req, res) => {
  const u = db.prepare('SELECT password FROM users WHERE id=?').get(req.uid);
  if (typeof req.body.current !== 'string' || !bcrypt.compareSync(req.body.current, u.password)) bad('Current password is incorrect', 403);
  db.prepare('UPDATE users SET password=? WHERE id=?').run(bcrypt.hashSync(checkPassword(req.body.next), 10), req.uid);
  res.json({ ok: 1 });
}));

/* ---------------------------------------------------------------- routines */
function routineBody(b) {
  const time = (v) => { if (v === undefined || v === null || v === '') return null; if (typeof v === 'string' && /^([01]\d|2[0-3]):[0-5]\d$/.test(v)) return v; return bad('Invalid time'); };
  const name = str(b.name, 100);
  if (!name) bad('Routine name is required');
  const days = [...new Set((Array.isArray(b.days) ? b.days : []).map(Number).filter((n) => Number.isInteger(n) && n >= 0 && n <= 6))].sort().join(',');
  if (!days) bad('Pick at least one day');
  if (!isDate(b.start_date)) bad('Start date is required');
  const ed = b.end_date ? (isDate(b.end_date) ? b.end_date : bad('Invalid end date')) : null;
  if (ed && ed < b.start_date) bad('End date must be after start date');
  return [name, str(b.description, 500), str(b.category, 40) || 'Other', time(b.start_time), time(b.end_time),
    ['low', 'medium', 'high'].includes(b.priority) ? b.priority : 'medium', days, b.start_date, ed, b.reminder ? 1 : 0];
}
const ensureCategory = (uid, c) => { if (!DEFAULT_CATEGORIES.includes(c)) db.prepare('INSERT OR IGNORE INTO categories(user_id,name) VALUES(?,?)').run(uid, c); };
const nextSort = (uid) => db.prepare('SELECT COALESCE(MAX(sort),0)+1 m FROM routines WHERE user_id=?').get(uid).m;

app.get('/api/categories', auth, h((req, res) => {
  res.json([...DEFAULT_CATEGORIES, ...db.prepare('SELECT name FROM categories WHERE user_id=? ORDER BY name').all(req.uid).map((x) => x.name)]);
}));
app.get('/api/routines', auth, h((req, res) => res.json(db.prepare('SELECT * FROM routines WHERE user_id=? ORDER BY sort,id').all(req.uid))));

app.post('/api/routines/reorder', auth, h((req, res) => {
  const ids = Array.isArray(req.body.ids) ? req.body.ids : bad('ids must be an array');
  const upd = db.prepare('UPDATE routines SET sort=? WHERE id=? AND user_id=?');
  db.transaction(() => ids.forEach((id, i) => upd.run(i, rid(id), req.uid)))();
  res.json({ ok: 1 });
}));

app.post('/api/routines', auth, h((req, res) => {
  const b = routineBody(req.body);
  ensureCategory(req.uid, b[2]);
  const id = db.prepare('INSERT INTO routines(user_id,name,description,category,start_time,end_time,priority,days,start_date,end_date,reminder,sort) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)')
    .run(req.uid, ...b, nextSort(req.uid)).lastInsertRowid;
  res.json({ id });
}));

app.put('/api/routines/:id', auth, h((req, res) => {
  const id = rid(req.params.id), b = routineBody(req.body);
  ensureCategory(req.uid, b[2]);
  const n = db.prepare('UPDATE routines SET name=?,description=?,category=?,start_time=?,end_time=?,priority=?,days=?,start_date=?,end_date=?,reminder=? WHERE id=? AND user_id=?').run(...b, id, req.uid).changes;
  if (!n) bad('Routine not found', 404);
  res.json({ ok: 1 });
}));

app.delete('/api/routines/:id', auth, h((req, res) => {
  if (!db.prepare('DELETE FROM routines WHERE id=? AND user_id=?').run(rid(req.params.id), req.uid).changes) bad('Routine not found', 404);
  res.json({ ok: 1 });
}));

app.post('/api/routines/:id/toggle', auth, h((req, res) => {
  if (!db.prepare('UPDATE routines SET active=1-active WHERE id=? AND user_id=?').run(rid(req.params.id), req.uid).changes) bad('Routine not found', 404);
  res.json({ ok: 1 });
}));

app.post('/api/routines/:id/duplicate', auth, h((req, res) => {
  const x = db.prepare('SELECT * FROM routines WHERE id=? AND user_id=?').get(rid(req.params.id), req.uid);
  if (!x) bad('Routine not found', 404);
  db.prepare('INSERT INTO routines(user_id,name,description,category,start_time,end_time,priority,days,start_date,end_date,reminder,active,sort) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)')
    .run(req.uid, (x.name + ' (copy)').slice(0, 100), x.description, x.category, x.start_time, x.end_time, x.priority, x.days, x.start_date, x.end_date, x.reminder, x.active, nextSort(req.uid));
  res.json({ ok: 1 });
}));

/* ---------------------------------------------------------------- tracking */
const addDays = (d, n) => { const x = new Date(d + 'T00:00:00Z'); x.setUTCDate(x.getUTCDate() + n); return x.toISOString().slice(0, 10); };
const scheduled = (r, d) => r.active && d >= r.start_date && (!r.end_date || d <= r.end_date) && r.days.split(',').includes(String(new Date(d + 'T00:00:00Z').getUTCDay()));

app.get('/api/day/:d', auth, h((req, res) => {
  const d = chkDate(req.params.d);
  const rs = db.prepare('SELECT * FROM routines WHERE user_id=? ORDER BY sort,id').all(req.uid);
  const tr = new Map(db.prepare('SELECT routine_id,status FROM tracking WHERE user_id=? AND date=?').all(req.uid, d).map((x) => [x.routine_id, x.status]));
  res.json(rs.filter((x) => scheduled(x, d)).map((x) => ({ ...x, status: tr.has(x.id) ? tr.get(x.id) : null })));
}));

app.put('/api/track', auth, h((req, res) => {
  const d = chkDate(req.body.date), id = rid(req.body.routine_id), s = req.body.status;
  if (s !== 0 && s !== 1 && s !== null) bad('Invalid status');
  if (!db.prepare('SELECT 1 FROM routines WHERE id=? AND user_id=?').get(id, req.uid)) bad('Routine not found', 404);
  if (s === null) db.prepare('DELETE FROM tracking WHERE routine_id=? AND date=? AND user_id=?').run(id, d, req.uid);
  else db.prepare('INSERT INTO tracking(user_id,routine_id,date,status,completed_at) VALUES(?,?,?,?,?) ON CONFLICT(routine_id,date) DO UPDATE SET status=excluded.status,completed_at=excluded.completed_at')
    .run(req.uid, id, d, s, s === 1 ? new Date().toISOString() : null);
  res.json({ ok: 1 });
}));

function range(uid, from, to) {
  const rs = db.prepare('SELECT * FROM routines WHERE user_id=?').all(uid), done = {};
  for (const t of db.prepare('SELECT routine_id,date FROM tracking WHERE user_id=? AND status=1 AND date BETWEEN ? AND ?').all(uid, from, to)) (done[t.date] = done[t.date] || new Set()).add(t.routine_id);
  const out = [];
  for (let d = from; d <= to; d = addDays(d, 1)) {
    const s = rs.filter((x) => scheduled(x, d));
    out.push({ date: d, total: s.length, done: done[d] ? s.filter((x) => done[d].has(x.id)).length : 0 });
  }
  return out;
}

app.get('/api/month/:ym', auth, h((req, res) => {
  const m = /^(\d{4})-(\d\d)$/.exec(req.params.ym);
  if (!m || +m[2] < 1 || +m[2] > 12) bad('Invalid month');
  const last = new Date(Date.UTC(+m[1], +m[2], 0)).getUTCDate(), days = {};
  for (const x of range(req.uid, req.params.ym + '-01', req.params.ym + '-' + String(last).padStart(2, '0'))) days[x.date] = x;
  res.json({ days });
}));

app.get('/api/stats', auth, h((req, res) => {
  const today = chkDate(req.query.today), min = getUser(req.uid).settings.min_pct;
  const first = db.prepare('SELECT MIN(start_date) m FROM routines WHERE user_id=?').get(req.uid).m, lim = addDays(today, -364);
  const all = range(req.uid, first && first > lim ? first : lim, today), act = all.filter((x) => x.total > 0);
  const pct = (x) => (x && x.total ? Math.round(x.done / x.total * 100) : 0);
  const agg = (a) => { const T = a.reduce((s, x) => s + x.total, 0); return T ? Math.round(a.reduce((s, x) => s + x.done, 0) / T * 100) : 0; };
  const ok = (x) => x.done / x.total * 100 >= min;
  let best = 0, run = 0;
  for (const x of act) { run = ok(x) ? run + 1 : 0; best = Math.max(best, run); }
  let i = act.length - 1;
  if (i >= 0 && act[i].date === today && !ok(act[i])) i--;
  let current = 0;
  while (i >= 0 && ok(act[i])) { current++; i--; }
  const week = all.slice(-7), month = all.filter((x) => x.date.startsWith(today.slice(0, 7)));
  res.json({
    today: pct(all[all.length - 1]), weekly: agg(week), monthly: agg(month),
    done: all.reduce((s, x) => s + x.done, 0), missed: all.reduce((s, x) => s + x.total - x.done, 0),
    current, best, active: db.prepare('SELECT COUNT(*) c FROM routines WHERE user_id=? AND active=1').get(req.uid).c, min,
    week: week.map((x) => ({ date: x.date, pct: pct(x), total: x.total })),
    month: month.map((x) => ({ date: x.date, pct: pct(x), total: x.total })),
  });
}));

/* -------------------------------------------------- 404s, SPA fallback, errors */
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
// The SPA uses #/hash routes, so the server only ever receives "/"; this also covers any direct deep link.
app.get('*', (req, res) => {
  if (path.extname(req.path)) return res.status(404).type('text').send('Not found');
  res.set('Cache-Control', 'no-cache').sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON in request body.' });
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Request body too large.' });
  if (err.v) return res.status(err.status || 400).json({ error: err.message });
  if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(409).json({ error: 'That value already exists.' });
  console.error(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`, err);
  res.status(500).json({ error: 'Something went wrong. Please try again.' });
});

/* ------------------------------------------------------------------ start */
const server = app.listen(PORT, () => {
  console.log(`Millionaire Tracking Habits running on port ${PORT} (${PROD ? 'production' : 'development'})`);
  console.log(`Database: ${DB_FILE}`);
  console.log(CROSS_SITE ? `CORS enabled for: ${CORS_ORIGINS.join(', ')} (cookie SameSite=${SAMESITE}; Secure)` : 'Same-origin mode (no CORS)');
});
server.on('error', (e) => fatal(e.code === 'EADDRINUSE' ? `Port ${PORT} is already in use.` : e.message));
const shutdown = (sig) => { console.log(`${sig} received, shutting down`); server.close(() => { try { db.close(); } catch { /* ignore */ } process.exit(0); }); setTimeout(() => process.exit(1), 10000).unref(); };
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('unhandledRejection', (e) => console.error('Unhandled rejection:', e));
