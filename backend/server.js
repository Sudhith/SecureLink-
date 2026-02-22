/**
 * Nexus Scanner — Backend Server
 * ─────────────────────────────────────────────────────────────
 * Proxies VirusTotal API calls so the key never reaches clients.
 * Also exposes /api/scan for direct chatbot / programmatic use.
 *
 * Start: node server.js  (or: npm start)
 * ─────────────────────────────────────────────────────────────
 */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import morgan from 'morgan';
import path from 'path';
import { fileURLToPath } from 'url';
import 'dotenv/config';

import { scanURL, getReport } from './virustotal.js';
import { validateURL } from './utils.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app  = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ──────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));   // CSP disabled for dev; enable in prod
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',')
    : '*',
  methods: ['GET', 'POST'],
}));
app.use(express.json());
app.use(morgan('dev'));

// Rate limiting: 30 requests / 15 min per IP (VirusTotal free = 4/min)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please wait before scanning again.' },
});
app.use('/api/', limiter);

// Serve the frontend
app.use(express.static(path.join(__dirname, '..', 'frontend')));

// ── Routes ──────────────────────────────────────────────────

/**
 * POST /api/scan
 * Body: { url: "https://example.com" }
 *
 * Returns a full threat intelligence report.
 * Designed to be called by both the web UI and chatbots.
 */
app.post('/api/scan', async (req, res) => {
  const { url } = req.body;

  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid `url` field in request body.' });
  }

  const cleaned = url.trim();
  const { valid, message } = validateURL(cleaned);
  if (!valid) return res.status(400).json({ error: message });

  try {
    console.log(`[SCAN] ${cleaned}`);
    const report = await scanURL(cleaned);
    res.json(report);
  } catch (err) {
    console.error('[SCAN ERROR]', err.message);
    const status = err.statusCode || 500;
    res.status(status).json({ error: err.message || 'Internal server error.' });
  }
});

/**
 * GET /api/report/:urlBase64
 * Fetch the latest cached VirusTotal report for a URL
 * (base64url-encode the URL to build the path param)
 */
app.get('/api/report/:urlBase64', async (req, res) => {
  try {
    const raw = Buffer.from(req.params.urlBase64, 'base64url').toString('utf8');
    const { valid, message } = validateURL(raw);
    if (!valid) return res.status(400).json({ error: message });

    const report = await getReport(raw);
    res.json(report);
  } catch (err) {
    console.error('[REPORT ERROR]', err.message);
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

/**
 * GET /api/health
 * Health check — confirms the server is running and API key is set.
 */
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    apiKeyConfigured: Boolean(process.env.VIRUSTOTAL_API_KEY),
    timestamp: new Date().toISOString(),
  });
});

// Catch-all — serve frontend for any unknown route
app.get('*', (_, res) => {
  res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html'));
});

// ── Start ───────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n  ◎ Nexus Scanner running at http://localhost:${PORT}`);
  console.log(`  · VirusTotal key: ${process.env.VIRUSTOTAL_API_KEY ? '✓ configured' : '✗ MISSING – set VIRUSTOTAL_API_KEY in .env'}`);
  console.log(`  · Environment  : ${process.env.NODE_ENV || 'development'}\n`);
});
