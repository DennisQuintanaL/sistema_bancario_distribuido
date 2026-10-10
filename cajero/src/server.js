import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import helmet from 'helmet';
import pg from 'pg';
import connectPgSimple from 'connect-pg-simple';
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes, timingSafeEqual, createCipheriv, createDecipheriv, createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

const app = express(); 
const runtime = process.env.VERCEL ? '/tmp/bank-atm' : path.join(root, '.runtime');
fs.mkdirSync(runtime, { recursive: true });

if (process.env.VERCEL && !process.env.NODES_DATABASE_URL) throw new Error('Configura NODES_DATABASE_URL para sesiones persistentes');
if (!process.env.SESSION_SECRET) throw new Error('Configura SESSION_SECRET');

app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'"], imgSrc: ["'self'", "data:"], connectSrc: ["'self'"], upgradeInsecureRequests: null } } }));
app.set('trust proxy', 1);
app.use(express.json({ limit: '16kb' }));

const sessionPool = process.env.NODES_DATABASE_URL ? new pg.Pool({ connectionString: process.env.NODES_DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 3 }) : null;
const PgSession = connectPgSimple(session);

app.use(session({
  name: 'atm_session',
  ...(sessionPool ? { store: new PgSession({ pool: sessionPool, tableName: 'atm_sessions', createTableIfMissing: true }) } : {}),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'strict', secure: process.env.COOKIE_SECURE === 'true' || !!process.env.VERCEL, maxAge: 30 * 60 * 1000 }
}));

// Resolución segura de la carpeta estática para Vercel
const publicPath = fs.existsSync(path.join(root, 'public')) ? path.join(root, 'public') : path.join(__dirname, 'public');
app.use(express.static(publicPath));

class ApiError extends Error { constructor(code, message, status = 409) { super(message); this.code = code; this.status = status; } }
const safeEqual = (a, b) => { const x = Buffer.from(a || ''), y = Buffer.from(b || ''); return x.length === y.length && timingSafeEqual(x, y); };
const cryptKey = createHash('sha256').update(process.env.SESSION_SECRET).digest();

function decryptSettings(text) { const d = JSON.parse(text); const dc = createDecipheriv('aes-256-gcm', cryptKey, Buffer.from(d.iv, 'hex')); dc.setAuthTag(Buffer.from(d.tag, 'hex')); return JSON.parse(Buffer.concat([dc.update(Buffer.from(d.data, 'hex')), dc.final()]).toString()); }

async function settings() {
  if (sessionPool) {
    const r = await sessionPool.query('SELECT encrypted_payload FROM public.node_configurations WHERE config_id=$1', [process.env.NODE_CONFIG_ID || 'atm-dennis']);
    if (r.rows.length) return decryptSettings(r.rows[0].encrypted_payload);
  }
  const f = path.join(runtime, 'config.enc');
  if (fs.existsSync(f)) return decryptSettings(fs.readFileSync(f, 'utf8'));
  return { central_url: process.env.CENTRAL_URL || 'http://127.0.0.1:18000', api_key: process.env.NODE_API_KEY || '' };
}

async function saveSettings(s) {
  const iv = randomBytes(12), c = createCipheriv('aes-256-gcm', cryptKey, iv);
  const data = Buffer.concat([c.update(JSON.stringify(s)), c.final()]);
  const payload = JSON.stringify({ iv: iv.toString('hex'), tag: c.getAuthTag().toString('hex'), data: data.toString('hex') });
  if (sessionPool) await sessionPool.query('INSERT INTO public.node_configurations (config_id,encrypted_payload) VALUES ($1,$2) ON CONFLICT (config_id) DO UPDATE SET encrypted_payload=excluded.encrypted_payload,updated_at=now()', [process.env.NODE_CONFIG_ID || 'atm-dennis', payload]);
  else fs.writeFileSync(path.join(runtime, 'config.enc'), payload, { mode: 0o600 });
}

async function central(method, route, body, headers = {}, cfg) {
  cfg ??= await settings();
  if (!cfg.api_key) throw new ApiError('NODE_NOT_CONFIGURED', 'Configura la conexión del cajero.', 422);
  let r;
  try {
    r = await fetch(cfg.central_url.replace(/\/$/, '') + '/api/v1' + route, {
      method,
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'X-API-Key': cfg.api_key, ...headers },
      ...(body ? { body: JSON.stringify(body) } : {}),
      signal: AbortSignal.timeout(20000)
    });
  } catch {
    throw new ApiError('CENTRAL_UNAVAILABLE', 'Banco central no disponible.', 503);
  }
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new ApiError(d.error?.code || 'CENTRAL_ERROR', d.error?.message || 'Solicitud rechazada por el banco central.', r.status);
  return d.data;
}

const data = (res, d, status = 200) => res.status(status).json({ data: d });
const admin = (req, res, next) => { if (!req.session.admin) throw new ApiError('UNAUTHORIZED', 'Inicia sesión como administrador.', 401); next(); };
const customer = (req, res, next) => { if (!req.session.customer) throw new ApiError('UNAUTHORIZED', 'Ingresa tu cuenta y PIN.', 401); next(); };
const csrf = (req, res, next) => { if (!safeEqual(req.session.csrf, req.get('X-CSRF-Token'))) throw new ApiError('CSRF_MISMATCH', 'Recarga la página para continuar.', 419); next(); };

const attempts = new Map();
function limit(req, res, next) {
  const ip = req.ip;
  const old = attempts.get(ip) || { n: 0, until: Date.now() + 60000 };
  if (old.until < Date.now()) { old.n = 0; old.until = Date.now() + 60000; }
  old.n++;
  attempts.set(ip, old);
  if (old.n > 15) throw new ApiError('RATE_LIMITED', 'Espera un minuto antes de volver a intentar.', 429);
  next();
}

function checkAccount(n) { if (!/^\d{12}$/.test(n || '')) throw new ApiError('INVALID_ACCOUNT', 'El número debe tener 12 dígitos.', 422); }
function cents(v) {
  if (!/^\d{1,10}(\.\d{1,2})?$/.test(String(v))) throw new ApiError('INVALID_AMOUNT', 'Monto inválido.', 422);
  const [a, b = ''] = String(v).split('.');
  const c = Number(a) * 100 + Number(b.padEnd(2, '0'));
  if (c <= 0) throw new ApiError('INVALID_AMOUNT', 'El monto debe ser positivo.', 422);
  return c;
}

const cashFile = path.join(runtime, 'cash.json');
async function updateCash(node) {
  fs.mkdirSync(runtime, { recursive: true });
  fs.writeFileSync(cashFile, JSON.stringify({ cash_cents: node.cash_cents, updated_at: new Date().toISOString(), node_id: node.id }));
  if (sessionPool) await sessionPool.query('INSERT INTO public.node_runtime (config_id,node_id,cash_cents) VALUES ($1,$2,$3) ON CONFLICT (config_id) DO UPDATE SET node_id=excluded.node_id,cash_cents=excluded.cash_cents,updated_at=now()', [process.env.NODE_CONFIG_ID || 'atm-dennis', node.id, node.cash_cents]);
}

let auditPool;
async function audit(result) {
  try {
    if (process.env.NODES_DATABASE_URL) {
      if (!auditPool) {
        const { Pool } = await import('pg');
        auditPool = new Pool({ connectionString: process.env.NODES_DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 2, connectionTimeoutMillis: 8000 });
      }
      await auditPool.query('INSERT INTO public.node_events (id,config_id,type,account_number,amount_cents,central_transaction_id,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (central_transaction_id) DO NOTHING', [result.transaction_id, process.env.NODE_CONFIG_ID || 'atm-dennis', result.type, result.account.account_number, cents(result.amount), result.transaction_id, result.timestamp]);
    } else fs.appendFileSync(path.join(runtime, 'events.jsonl'), JSON.stringify(result) + '\n');
  } catch {
    fs.appendFileSync(path.join(runtime, 'pending-audit.jsonl'), JSON.stringify(result) + '\n');
  }
}

app.get('/api/v1/health', (req, res) => data(res, { service: 'cajero', status: 'ok', local_database: process.env.NODES_DATABASE_URL ? 'Supabase PostgreSQL' : 'Archivo local' }));
app.get('/api/v1/csrf', (req, res) => { req.session.csrf ??= randomBytes(24).toString('hex'); data(res, { csrf_token: req.session.csrf }); });
app.post('/api/v1/auth/login', csrf, limit, (req, res, next) => {
  if (!safeEqual(req.body.email, process.env.ADMIN_EMAIL || 'atm@banco.local') || !safeEqual(req.body.password, process.env.ADMIN_PASSWORD) || !process.env.ADMIN_PASSWORD) throw new ApiError('INVALID_CREDENTIALS', 'Credenciales incorrectas.', 401);
  req.session.regenerate(e => {
    if (e) return next(e);
    req.session.admin = true;
    req.session.csrf = randomBytes(24).toString('hex');
    data(res, { csrf_token: req.session.csrf });
  });
});
app.post('/api/v1/auth/logout', csrf, (req, res) => req.session.destroy(() => data(res, { message: 'Sesión cerrada' })));
app.get('/api/v1/config', admin, async (req, res) => { const s = await settings(); data(res, { central_url: s.central_url, configured: !!s.api_key }); });
app.put('/api/v1/config', admin, csrf, async (req, res) => {
  const s = req.body;
  let url;
  try { url = new URL(s.central_url); } catch { throw new ApiError('INVALID_URL', 'URL central inválida.', 422); }
  if (!['http:', 'https:'].includes(url.protocol) || typeof s.api_key !== 'string' || s.api_key.length > 200) throw new ApiError('INVALID_CONFIG', 'Configuración inválida.', 422);
  const cfg = { central_url: url.href.replace(/\/$/, ''), api_key: s.api_key };
  const node = await central('GET', '/node', null, {}, cfg);
  if (node.type !== 'atm') throw new ApiError('WRONG_NODE_TYPE', 'La API key no pertenece a un cajero.', 422);
  await saveSettings(cfg);
  await updateCash(node);
  data(res, node);
});
app.get('/api/v1/node', async (req, res) => { const node = await central('GET', '/node'); await updateCash(node); data(res, { name: node.name, cash: node.cash, cash_cents: node.cash_cents, status: node.status }); });
app.post('/api/v1/customer/login', csrf, limit, async (req, res, next) => {
  checkAccount(req.body.account_number);
  if (!/^\d{4}$/.test(req.body.pin || '')) throw new ApiError('INVALID_PIN', 'El PIN debe tener cuatro dígitos.', 422);
  const a = await central('GET', `/accounts/${req.body.account_number}/balance`, null, { 'X-Account-Pin': req.body.pin });
  const c = { account_number: req.body.account_number, pin: req.body.pin };
  req.session.regenerate(e => {
    if (e) return next(e);
    req.session.customer = c;
    req.session.csrf = randomBytes(24).toString('hex');
    data(res, { account: a, csrf_token: req.session.csrf });
  });
});
app.post('/api/v1/customer/logout', csrf, (req, res) => req.session.destroy(() => data(res, { message: 'Sesión finalizada' })));
app.get('/api/v1/balance', customer, async (req, res) => data(res, await central('GET', `/accounts/${req.session.customer.account_number}/balance`, null, { 'X-Account-Pin': req.session.customer.pin })));

for (const [route, kind] of [['withdrawals', 'withdrawal'], ['deposits', 'deposit'], ['transfers', 'transfer']]) app.post('/api/v1/' + route, customer, csrf, async (req, res) => {
  const amount = cents(req.body.amount);
  const key = req.get('Idempotency-Key');
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(key || '')) throw new ApiError('IDEMPOTENCY_REQUIRED', 'Se requiere Idempotency-Key.', 422);
  const customer = req.session.customer;
  const body = kind === 'transfer' ? { source_account: customer.account_number, destination_account: req.body.destination_account, amount: req.body.amount } : { account_number: customer.account_number, amount: req.body.amount };
  if (kind === 'transfer') checkAccount(body.destination_account);
  const n = await central('GET', '/node');
  await updateCash(n);
  if (kind === 'withdrawal') {
    const local = JSON.parse(fs.readFileSync(cashFile));
    if (local.cash_cents < amount) throw new ApiError('INSUFFICIENT_CASH', 'El cajero no dispone de ese efectivo.', 409);
  }
  const result = await central('POST', '/' + route, body, { 'Idempotency-Key': key, 'X-Account-Pin': customer.pin });
  await updateCash({ cash_cents: Math.round(Number(result.node_cash) * 100), id: n.id });
  await audit(result);
  data(res, result, result.replayed ? 200 : 201);
});

app.get('/api/v1/transactions', async (req, res) => {
  if (!req.session.admin && !req.session.customer) throw new ApiError('UNAUTHORIZED', 'Inicia sesión.', 401);
  const q = new URLSearchParams();
  if (req.session.customer) q.set('account_number', req.session.customer.account_number);
  else if (req.query.account_number) q.set('account_number', req.query.account_number);
  data(res, await central('GET', '/transactions' + (q.size ? '?' + q : '')));
});

// Ruta HTML principal fallback
app.get('/', (req, res) => {
  const indexPath = path.join(publicPath, 'index.html');
  if (fs.existsSync(indexPath)) res.sendFile(indexPath);
  else res.send('API del Cajero Automático Operativa');
});

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  res.status(err.status || 500).json({ error: { code: err.code || 'INTERNAL_ERROR', message: err.status ? err.message : 'No fue posible completar la operación.' } });
});

if (process.env.NODE_ENV !== 'test' && !process.env.VERCEL) app.listen(Number(process.env.PORT || 3000), '0.0.0.0', () => console.log('Cajero disponible en http://0.0.0.0:' + Number(process.env.PORT || 3000)));

export default app;
