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

// 1. Configuración de Rutas Absolutas para Vercel / Local
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

const app = express();

// Manejo del directorio runtime para archivos temporales
const runtime = process.env.VERCEL ? '/tmp/bank-atm' : path.join(root, '.runtime');
fs.mkdirSync(runtime, { recursive: true });

// 2. Validaciones de Variables de Entorno
if (process.env.VERCEL && !process.env.NODES_DATABASE_URL) {
  throw new Error('Configura NODES_DATABASE_URL para sesiones persistentes');
}
if (!process.env.SESSION_SECRET) {
  throw new Error('Configura SESSION_SECRET');
}

// 3. Middlewares Principales y Seguridad
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      upgradeInsecureRequests: null
    }
  }
}));

app.set('trust proxy', 1);
app.use(express.json({ limit: '16kb' }));

// 4. Configuración de Sesiones con PostgreSQL
const sessionPool = process.env.NODES_DATABASE_URL ? new pg.Pool({
  connectionString: process.env.NODES_DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 3
}) : null;

const PgSession = connectPgSimple(session);

app.use(session({
  store: sessionPool ? new PgSession({ pool: sessionPool, createTableIfMissing: true }) : undefined,
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production' || !!process.env.VERCEL,
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24 // 1 día
  }
}));

// 5. Rutas API

// Ruta para entregar el token CSRF al frontend
app.get('/api/v1/csrf', (req, res) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = randomBytes(32).toString('hex');
  }
  res.json({ csrfToken: req.session.csrfToken });
});

// 6. Servir Archivos Estáticos (Garantiza encontrar app.js y bank.css)
const publicPath = fs.existsSync(path.join(root, 'public')) 
  ? path.join(root, 'public') 
  : path.join(__dirname, 'public');

app.use(express.static(publicPath));

// Ruta principal fallback
app.get('/', (req, res) => {
  const indexPath = path.join(publicPath, 'index.html');
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.send('API del Cajero Automático Operativa');
  }
});

// 7. Manejo del Servidor Local vs Serverless en Vercel
if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Cajero corriendo localmente en el puerto ${PORT}`);
  });
}

// Exportación obligatoria para Vercel
export default app;
