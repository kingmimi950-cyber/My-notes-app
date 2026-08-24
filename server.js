require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error('Missing JWT_SECRET. Copy .env.example to .env and set one before starting the server.');
  process.exit(1);
}

app.use(cors());
app.use(express.json({ limit: '2mb' }));

// ---------- Uploads ----------
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const safeExt = ['.png', '.jpg', '.jpeg', '.gif', '.webp'].includes(ext) ? ext : '';
    cb(null, `${Date.now()}-${crypto.randomBytes(6).toString('hex')}${safeExt}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 8 * 1024 * 1024 }, // 8MB
  fileFilter: (req, file, cb) => {
    const ok = /^image\/(png|jpe?g|gif|webp)$/.test(file.mimetype);
    cb(ok ? null : new Error('Only image files are allowed'), ok);
  }
});
app.use('/uploads', express.static(uploadDir));

// ---------- Auth helpers ----------
function signToken(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
}

function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing auth token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.id;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ---------- Auth routes ----------
app.post('/api/auth/register', async (req, res) => {
  const { email, password } = req.body || {};
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Enter a valid email address' });
  if (typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase());
  if (existing) return res.status(409).json({ error: 'An account with that email already exists' });

  const passwordHash = await bcrypt.hash(password, 12);
  const cryptoSalt = crypto.randomBytes(16).toString('hex');
  const now = Date.now();

  const result = db.prepare(
    'INSERT INTO users (email, password_hash, crypto_salt, created_at) VALUES (?, ?, ?, ?)'
  ).run(email.toLowerCase(), passwordHash, cryptoSalt, now);

  const user = { id: result.lastInsertRowid, email: email.toLowerCase() };
  res.json({ token: signToken(user), email: user.email, cryptoSalt });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!isValidEmail(email) || typeof password !== 'string') {
    return res.status(400).json({ error: 'Enter a valid email and password' });
  }

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
  if (!user) return res.status(401).json({ error: 'Incorrect email or password' });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Incorrect email or password' });

  res.json({ token: signToken(user), email: user.email, cryptoSalt: user.crypto_salt });
});

app.get('/api/auth/me', authenticate, (req, res) => {
  const user = db.prepare('SELECT id, email, crypto_salt FROM users WHERE id = ?').get(req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ email: user.email, cryptoSalt: user.crypto_salt });
});

// ---------- Entry routes ----------
function serializeEntry(row) {
  return {
    id: row.id,
    title: row.title,
    body: row.body,
    tags: JSON.parse(row.tags || '[]'),
    attachments: JSON.parse(row.attachments || '[]'),
    encrypted: !!row.encrypted,
    iv: row.iv || null,
    created: row.created_at,
    updated: row.updated_at
  };
}

app.get('/api/entries', authenticate, (req, res) => {
  const rows = db.prepare('SELECT * FROM entries WHERE user_id = ? ORDER BY updated_at DESC').all(req.userId);
  res.json(rows.map(serializeEntry));
});

app.post('/api/entries', authenticate, (req, res) => {
  const { title = '', body = '', tags = [], attachments = [], encrypted = false, iv = null } = req.body || {};
  const now = Date.now();
  const result = db.prepare(`
    INSERT INTO entries (user_id, title, body, tags, attachments, encrypted, iv, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(req.userId, title, body, JSON.stringify(tags), JSON.stringify(attachments), encrypted ? 1 : 0, iv, now, now);

  const row = db.prepare('SELECT * FROM entries WHERE id = ?').get(result.lastInsertRowid);
  res.status(201).json(serializeEntry(row));
});

app.put('/api/entries/:id', authenticate, (req, res) => {
  const existing = db.prepare('SELECT * FROM entries WHERE id = ? AND user_id = ?').get(req.params.id, req.userId);
  if (!existing) return res.status(404).json({ error: 'Entry not found' });

  const { title, body, tags, attachments, encrypted, iv } = req.body || {};
  const now = Date.now();

  db.prepare(`
    UPDATE entries SET
      title = COALESCE(?, title),
      body = COALESCE(?, body),
      tags = COALESCE(?, tags),
      attachments = COALESCE(?, attachments),
      encrypted = COALESCE(?, encrypted),
      iv = ?,
      updated_at = ?
    WHERE id = ? AND user_id = ?
  `).run(
    title ?? null,
    body ?? null,
    tags ? JSON.stringify(tags) : null,
    attachments ? JSON.stringify(attachments) : null,
    typeof encrypted === 'boolean' ? (encrypted ? 1 : 0) : null,
    iv !== undefined ? iv : existing.iv,
    now,
    req.params.id,
    req.userId
  );

  const row = db.prepare('SELECT * FROM entries WHERE id = ?').get(req.params.id);
  res.json(serializeEntry(row));
});

app.delete('/api/entries/:id', authenticate, (req, res) => {
  const result = db.prepare('DELETE FROM entries WHERE id = ? AND user_id = ?').run(req.params.id, req.userId);
  if (result.changes === 0) return res.status(404).json({ error: 'Entry not found' });
  res.json({ ok: true });
});

// ---------- Upload route ----------
app.post('/api/upload', authenticate, (req, res) => {
  upload.single('photo')(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message });
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    res.json({ url: `/uploads/${req.file.filename}` });
  });
});

// ---------- Static frontend ----------
app.use(express.static(path.join(__dirname, '..', 'public')));
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api') || req.path.startsWith('/uploads')) return next();
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Fieldnotes server running at http://localhost:${PORT}`);
});
