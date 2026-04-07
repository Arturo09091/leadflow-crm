const express = require('express');
const session = require('express-session');
const bcrypt  = require('bcryptjs');
const path    = require('path');
const fs      = require('fs');

// ── Simple in-memory rate limiter (no extra packages) ────────────
const loginAttempts = new Map();
function isRateLimited(ip) {
  const now  = Date.now();
  const win  = 15 * 60 * 1000; // 15 min window
  const max  = 10;              // max attempts per window
  let entry  = loginAttempts.get(ip);
  if (!entry || now > entry.resetAt) { entry = { count: 0, resetAt: now + win }; loginAttempts.set(ip, entry); }
  entry.count++;
  return entry.count > max;
}
// Clean up old entries every 30 min to avoid memory leak
setInterval(() => { const now = Date.now(); loginAttempts.forEach((v, k) => { if (now > v.resetAt) loginAttempts.delete(k); }); }, 30 * 60 * 1000);

// PostgreSQL (Railway production) — only loaded when DATABASE_URL is set
let pool = null;
if (process.env.DATABASE_URL) {
  const { Pool } = require('pg');
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
  });
  console.log('🗄️  PostgreSQL conectado');
}

const app       = express();
const PORT      = process.env.PORT || 3000;
const AUTH_FILE = path.join(__dirname, 'auth.json');
const DATA_DIR  = path.join(__dirname, 'data');

if (!pool) fs.mkdirSync(DATA_DIR, { recursive: true });

// ── Middleware ────────────────────────────────────────────────────

if (!process.env.SESSION_SECRET) console.warn('⚠️  SESSION_SECRET no configurado — configuralo en Railway');

app.use(express.json({ limit: '50kb' }));
app.use(express.urlencoded({ extended: true, limit: '50kb' }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'lf-change-in-prod-2026',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge:   7 * 24 * 60 * 60 * 1000,
    httpOnly: true,                                        // no accesible por JS del cliente
    secure:   process.env.NODE_ENV === 'production',      // solo HTTPS en prod
    sameSite: 'lax',                                      // protege contra CSRF
  },
}));

// ── DB setup (PostgreSQL) ────────────────────────────────────────

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS crm_users (
      username     TEXT PRIMARY KEY,
      name         TEXT NOT NULL,
      role         TEXT NOT NULL DEFAULT 'client',
      password_hash TEXT NOT NULL,
      webhook_key  TEXT
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS leads (
      id         TEXT PRIMARY KEY,
      username   TEXT NOT NULL,
      data       JSONB NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // Migrate from auth.json on first deploy
  const { rows } = await pool.query('SELECT COUNT(*) as c FROM crm_users');
  if (rows[0].c === '0' && fs.existsSync(AUTH_FILE)) {
    const auth = JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8'));
    for (const u of auth.users) {
      await pool.query(
        `INSERT INTO crm_users (username, name, role, password_hash, webhook_key)
         VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`,
        [u.username, u.name, u.role, u.passwordHash, u.webhookKey || null]
      );
    }
    console.log('✅ auth.json migrado a PostgreSQL');
  }
}

// ── Storage abstraction ───────────────────────────────────────────

// AUTH

async function getUsers() {
  if (pool) {
    const { rows } = await pool.query('SELECT * FROM crm_users');
    return rows.map(r => ({ username: r.username, name: r.name, role: r.role, passwordHash: r.password_hash, webhookKey: r.webhook_key }));
  }
  try { return JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8')).users; } catch { return []; }
}

async function findUser(username) {
  if (pool) {
    const { rows } = await pool.query('SELECT * FROM crm_users WHERE username=$1', [username]);
    if (!rows[0]) return null;
    const r = rows[0];
    return { username: r.username, name: r.name, role: r.role, passwordHash: r.password_hash, webhookKey: r.webhook_key };
  }
  try { return JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8')).users.find(u => u.username === username); } catch { return null; }
}

async function upsertUser(user) {
  if (pool) {
    await pool.query(
      `INSERT INTO crm_users (username, name, role, password_hash, webhook_key)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (username) DO UPDATE SET name=$2, role=$3, password_hash=$4, webhook_key=$5`,
      [user.username, user.name, user.role, user.passwordHash, user.webhookKey || null]
    );
    return;
  }
  const authData = fs.existsSync(AUTH_FILE) ? JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8')) : { users: [] };
  const idx = authData.users.findIndex(u => u.username === user.username);
  if (idx >= 0) authData.users[idx] = user; else authData.users.push(user);
  fs.writeFileSync(AUTH_FILE, JSON.stringify(authData, null, 2));
}

async function deleteUser(username) {
  if (pool) {
    await pool.query('DELETE FROM crm_users WHERE username=$1', [username]);
    await pool.query('DELETE FROM leads WHERE username=$1', [username]);
    return;
  }
  const authData = JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8'));
  authData.users = authData.users.filter(u => u.username !== username);
  fs.writeFileSync(AUTH_FILE, JSON.stringify(authData, null, 2));
  const f = path.join(DATA_DIR, `leads_${username}.json`);
  if (fs.existsSync(f)) fs.unlinkSync(f);
}

// LEADS

async function readLeads(username) {
  if (pool) {
    const { rows } = await pool.query('SELECT data FROM leads WHERE username=$1 ORDER BY created_at DESC', [username]);
    return rows.map(r => r.data);
  }
  const f = path.join(DATA_DIR, `leads_${username}.json`);
  try { return fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, 'utf8')) : []; } catch { return []; }
}

async function upsertLead(username, lead) {
  if (pool) {
    await pool.query(
      `INSERT INTO leads (id, username, data) VALUES ($1,$2,$3)
       ON CONFLICT (id) DO UPDATE SET data=$3`,
      [lead.id, username, lead]
    );
    return;
  }
  const f      = path.join(DATA_DIR, `leads_${username}.json`);
  const leads  = fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, 'utf8')) : [];
  const idx    = leads.findIndex(l => l.id === lead.id);
  if (idx >= 0) leads[idx] = lead; else leads.unshift(lead);
  fs.writeFileSync(f, JSON.stringify(leads, null, 2));
}

async function deleteLead(username, id) {
  if (pool) {
    await pool.query('DELETE FROM leads WHERE id=$1 AND username=$2', [id, username]);
    return;
  }
  const f     = path.join(DATA_DIR, `leads_${username}.json`);
  const leads = fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, 'utf8')) : [];
  fs.writeFileSync(f, JSON.stringify(leads.filter(l => l.id !== id), null, 2));
}

async function leadsCount(username) {
  if (pool) {
    const { rows } = await pool.query('SELECT COUNT(*) as c FROM leads WHERE username=$1', [username]);
    return parseInt(rows[0].c);
  }
  const f = path.join(DATA_DIR, `leads_${username}.json`);
  try { return fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, 'utf8')).length : 0; } catch { return 0; }
}

async function leadsCountLast30(username) {
  const since = new Date(); since.setDate(since.getDate() - 30);
  const sinceISO = since.toISOString().split('T')[0];
  if (pool) {
    const { rows } = await pool.query(
      "SELECT COUNT(*) as c FROM leads WHERE username=$1 AND data->>'createdAt' >= $2",
      [username, sinceISO]
    );
    return parseInt(rows[0].c);
  }
  const f = path.join(DATA_DIR, `leads_${username}.json`);
  try {
    const leads = fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, 'utf8')) : [];
    return leads.filter(l => (l.createdAt || '') >= sinceISO).length;
  } catch { return 0; }
}

// ── Bootstrap ─────────────────────────────────────────────────────

function uid()         { return Date.now().toString(36) + Math.random().toString(36).slice(2, 7); }
function wKey()        { return 'wh-' + Math.random().toString(36).slice(2,10) + Math.random().toString(36).slice(2,10); }
function todayISO()    { return new Date().toISOString().split('T')[0]; }
function tomorrowISO() { const d = new Date(); d.setDate(d.getDate() + 1); return d.toISOString().split('T')[0]; }

// Known accounts to seed into PostgreSQL on first deploy.
// Passwords are bcrypt hashes — plain-text passwords are never stored here.
const SEED_USERS = [
  { username: 'arturo',  name: 'Arturo Abellan', role: 'admin',  passwordHash: '$2b$10$ro7AZNNOSND2QSFpILCZGea23FqSXrwdzhvEFALrUc3vK2bJ.S45y', webhookKey: null },
  { username: 'hgroup',  name: 'H Group',        role: 'client', passwordHash: '$2b$10$cZNqjV966pvuiJkpSgQte.x7Y./51U6O69V8tC6kgkSTxdWbTcjO2', webhookKey: 'hgrp-3xcb2txiapy8sl30' },
  { username: 'lucas',   name: 'paco',           role: 'client', passwordHash: '$2b$10$2ZcgxuxaEDPutsBPd9y9mOWaP0rxT2fkAYCQcVXCrrmxDhUUMUiAq', webhookKey: 'wh-r7xqixhbj9uq2lj7' },
  { username: 'pepe',    name: 'vcbn',           role: 'client', passwordHash: '$2b$10$8iRznQwiC0kjEKTWi6xndOrbaJ.4snPVLPn2EfikROCS33VRC2t7y', webhookKey: 'wh-9gpod0xglt4twqh5' },
];

async function bootstrap() {
  if (pool) await initDB();

  const users = await getUsers();
  if (users.length === 0) {
    // Seed all known accounts (preserves passwords and webhook keys)
    for (const u of SEED_USERS) {
      await upsertUser(u);
    }
    console.log(`\n✅ ${SEED_USERS.length} cuentas migradas a PostgreSQL\n`);
  }
}

// ── Auth middleware ───────────────────────────────────────────────

const PUBLIC = ['/login', '/auth/login'];

function requireAuth(req, res, next) {
  if (PUBLIC.includes(req.path)) return next();
  if (req.path.startsWith('/api/webhook/')) return next();
  if (!req.session.authenticated) {
    if (req.path.startsWith('/api/') || req.path.startsWith('/admin/')) return res.status(401).json({ error: 'No autorizado' });
    return res.redirect('/login');
  }
  next();
}

function requireAdmin(req, res, next) {
  if (req.session.role !== 'admin') return res.status(403).json({ error: 'Solo administradores' });
  next();
}

// Block server-side files from being served statically — unconditional, no auth bypass
const BLOCKED_PATHS = new Set(['/server.js', '/auth.json', '/package.json', '/package-lock.json', '/railway.json', '/.gitignore', '/.env']);
app.use((req, res, next) => {
  const p = req.path.toLowerCase();
  if (BLOCKED_PATHS.has(p) || p.startsWith('/data/') || p.startsWith('/node_modules/') || p.startsWith('/.'))
    return res.status(404).end();
  next();
});

app.use(requireAuth);
app.use(express.static(path.join(__dirname)));

// ── Auth routes ───────────────────────────────────────────────────

app.post('/auth/login', async (req, res) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'unknown';
  if (isRateLimited(ip)) return res.status(429).json({ ok: false, error: 'Demasiados intentos. Esperá 15 minutos.' });

  const { username, password } = req.body;
  const user = await findUser(username);
  if (!user || !bcrypt.compareSync(password, user.passwordHash))
    return res.json({ ok: false, error: 'Usuario o contraseña incorrectos' });
  req.session.authenticated = true;
  req.session.username = user.username;
  req.session.name     = user.name;
  req.session.role     = user.role;
  res.json({ ok: true, role: user.role, name: user.name });
});

app.get('/auth/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));

app.post('/auth/change-password', async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const user = await findUser(req.session.username);
  if (!user || !bcrypt.compareSync(currentPassword, user.passwordHash))
    return res.json({ ok: false, error: 'Contraseña actual incorrecta' });
  user.passwordHash = bcrypt.hashSync(newPassword, 10);
  await upsertUser(user);
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  if (!req.session.authenticated) return res.status(401).json({ error: 'No autorizado' });
  res.json({ username: req.session.username, name: req.session.name, role: req.session.role });
});

// ── Admin routes ──────────────────────────────────────────────────

app.get('/admin/users', requireAdmin, async (req, res) => {
  const users = await getUsers();
  const result = await Promise.all(users.map(async u => ({
    username:    u.username,
    name:        u.name,
    role:        u.role,
    webhookKey:  u.webhookKey,
    leadsCount:  await leadsCount(u.username),
    leadsLast30: await leadsCountLast30(u.username),
  })));
  res.json(result);
});

app.post('/admin/users', requireAdmin, async (req, res) => {
  const { username, name, password, role = 'client' } = req.body;
  if (!username || !name || !password) return res.status(400).json({ error: 'Faltan campos' });
  const existing = await findUser(username);
  if (existing) return res.status(409).json({ error: 'El usuario ya existe' });
  const key = wKey();
  await upsertUser({ username, name, role, passwordHash: bcrypt.hashSync(password, 10), webhookKey: key });
  res.json({ ok: true, username, name, role, webhookKey: key });
});

app.delete('/admin/users/:username', requireAdmin, async (req, res) => {
  if (req.params.username === req.session.username) return res.status(400).json({ error: 'No podés eliminarte a vos mismo' });
  await deleteUser(req.params.username);
  res.json({ ok: true });
});

app.post('/admin/users/:username/reset-password', requireAdmin, async (req, res) => {
  const user = await findUser(req.params.username);
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
  user.passwordHash = bcrypt.hashSync(req.body.newPassword, 10);
  await upsertUser(user);
  res.json({ ok: true });
});

// ── Leads API ─────────────────────────────────────────────────────

app.get('/api/leads', async (req, res) => res.json(await readLeads(req.session.username)));

app.post('/api/leads', async (req, res) => {
  const lead = { ...req.body, id: req.body.id || uid() };
  await upsertLead(req.session.username, lead);
  res.json(lead);
});

app.delete('/api/leads/:id', async (req, res) => {
  await deleteLead(req.session.username, req.params.id);
  res.json({ ok: true });
});

// ── Make Webhook ──────────────────────────────────────────────────

app.post('/api/webhook/:key', async (req, res) => {
  // Validate key format to avoid unnecessary DB lookups
  if (!/^[\w\-]{8,40}$/.test(req.params.key)) return res.status(400).json({ error: 'Key inválida' });

  const users = await getUsers();
  const user  = users.find(u => u.webhookKey === req.params.key);
  if (!user) return res.status(404).json({ error: 'Webhook key no válida' });

  const b    = req.body;
  const trunc = (s, n) => String(s || '').slice(0, n); // prevent oversized fields
  const lead = {
    id: uid(), name: trunc(b.name, 120) || 'Sin nombre', phone: trunc(b.phone, 30),
    email: trunc(b.email, 120), source: trunc(b.source, 60) || 'Facebook Ads',
    campaign: trunc(b.campaign, 120), adSet: trunc(b.adSet, 120),
    stage: 'new', notes: trunc(b.notes, 1000),
    createdAt: b.createdAt || todayISO(), followUpDate: tomorrowISO(), value: Number(b.value) || 0,
  };
  await upsertLead(user.username, lead);
  console.log(`📥 [Make → ${user.name}] ${lead.name} | ${lead.phone}`);
  res.json({ ok: true, lead });
});

// ── Pages ─────────────────────────────────────────────────────────

app.get('/login', (req, res) => {
  if (req.session.authenticated) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'login.html'));
});
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'leadflow-crm.html')));

// ── Start ─────────────────────────────────────────────────────────

bootstrap().then(() => {
  app.listen(PORT, () => {
    console.log(`✅  LAX Group CRM  →  http://localhost:${PORT}`);
    console.log(`📡  Webhooks      →  http://localhost:${PORT}/api/webhook/:key`);
  });
}).catch(err => { console.error('Error al arrancar:', err); process.exit(1); });
