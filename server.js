require('dotenv').config();
const express = require('express');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const app = express();
const isProduction = process.env.NODE_ENV === 'production';
const config = {
  jwtSecret: process.env.JWT_SECRET,
  issuer: process.env.JWT_ISSUER || 'saulr-marketplace',
  audience: process.env.JWT_AUDIENCE || 'saulr-web',
  sessionHours: Math.min(24, Math.max(1, Number(process.env.SESSION_TTL_HOURS || 8))),
  secureCookies: isProduction || process.env.SECURE_COOKIES === 'true'
};
if (isProduction && (!config.jwtSecret || config.jwtSecret.length < 32)) throw new Error('JWT_SECRET must be at least 32 characters in production.');
if (!config.jwtSecret) config.jwtSecret = crypto.randomBytes(48).toString('base64url');
app.disable('x-powered-by');
app.use((req, res, next) => {
  req.id = crypto.randomUUID();
  res.set({
    'X-Request-ID': req.id, 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin', 'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https://images.unsplash.com https://i.pravatar.cc; connect-src 'self'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
  });
  if (isProduction) res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});
app.use(express.json({ limit: '5mb', strict: true, type: 'application/json' }));
app.use(express.static(path.join(__dirname, 'public')));

// Set DATABASE_URL in .env to use PostgreSQL. The UI includes demo items until then.
const pool = process.env.DATABASE_URL ? new Pool({ connectionString: process.env.DATABASE_URL }) : null;
if (pool) Promise.all([
  pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS whatsapp VARCHAR(25)'),
  pool.query('ALTER TABLE listings ADD COLUMN IF NOT EXISTS buyer_id INTEGER REFERENCES users(id) ON DELETE SET NULL'),
  pool.query('ALTER TABLE messages ADD COLUMN IF NOT EXISTS listing_id INTEGER REFERENCES listings(id) ON DELETE SET NULL'),
  pool.query('CREATE TABLE IF NOT EXISTS favorites (user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, listing_id INTEGER REFERENCES listings(id) ON DELETE CASCADE, created_at TIMESTAMPTZ DEFAULT NOW(), PRIMARY KEY (user_id, listing_id))'),
  pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ'),
  pool.query("CREATE TABLE IF NOT EXISTS audit_events (id BIGSERIAL PRIMARY KEY, actor_id INTEGER, action VARCHAR(80) NOT NULL, resource_type VARCHAR(80), resource_id VARCHAR(80), result VARCHAR(20) NOT NULL DEFAULT 'success', request_id UUID NOT NULL, metadata JSONB NOT NULL DEFAULT '{}', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())"),
  pool.query('CREATE TABLE IF NOT EXISTS revoked_tokens (jti UUID PRIMARY KEY, expires_at TIMESTAMPTZ NOT NULL)'),
  pool.query('CREATE INDEX IF NOT EXISTS audit_events_created_idx ON audit_events(created_at)'),
  pool.query('CREATE INDEX IF NOT EXISTS revoked_tokens_expiry_idx ON revoked_tokens(expires_at)')
  , pool.query('CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_unique ON users (LOWER(username)) WHERE deleted_at IS NULL')
]).catch(() => console.error(JSON.stringify({ level: 'error', component: 'database', message: 'Database migration failed' })));
const apiError = (res, status, code, error) => res.status(status).json({ error, code, requestId: res.req.id });
const audit = (req, action, metadata = {}) => {
  const safe = { ...metadata }; delete safe.password; delete safe.token;
  console.log(JSON.stringify({ level: 'info', component: 'audit', requestId: req.id, actorId: req.user?.id || null, action, ...safe }));
  if (pool) pool.query('INSERT INTO audit_events (actor_id,action,resource_type,resource_id,result,request_id,metadata) VALUES ($1,$2,$3,$4,$5,$6,$7)', [req.user?.id || null, action, safe.resourceType || null, safe.resourceId || null, safe.result || 'success', req.id, JSON.stringify(safe)]).catch(() => {});
};
const parseId = (value, field = 'ID') => { const id = Number(value); if (!Number.isSafeInteger(id) || id < 1) throw new Error(`Invalid ${field}.`); return id; };
const plainText = (value, field, max, required = false) => { if (value === undefined || value === null) { if (required) throw new Error(`Invalid ${field}.`); return ''; } if (typeof value !== 'string') throw new Error(`Invalid ${field}.`); const out = value.trim(); if ((required && !out) || out.length > max || /[<>\u0000-\u001f]/.test(out)) throw new Error(`Invalid ${field}.`); return out; };
const validateImage = (value, field = 'image') => { if (typeof value !== 'string' || value.length > 1500000 || !/^data:image\/(?:png|jpeg|webp);base64,[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new Error(`Invalid ${field}.`); return value; };
const getCookie = (req, name) => (req.headers.cookie || '').split(';').map(v => v.trim()).find(v => v.startsWith(`${name}=`))?.slice(name.length + 1);
const csrf = (req, res, next) => { const expected = getCookie(req, 'csrf'), actual = req.get('x-csrf-token'); if (!expected || !actual || expected.length !== actual.length || !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(actual))) return apiError(res, 403, 'CSRF_FAILED', 'Your session could not be verified. Refresh and try again.'); next(); };
const setSession = (res, user) => { const token = makeToken(user); const csrfToken = crypto.randomBytes(32).toString('base64url'); const maxAge = config.sessionHours * 3600000; res.cookie('session', token, { httpOnly: true, secure: config.secureCookies, sameSite: 'lax', maxAge, path: '/' }); res.cookie('csrf', csrfToken, { httpOnly: false, secure: config.secureCookies, sameSite: 'lax', maxAge, path: '/' }); return csrfToken; };
const requireDatabase = (res) => {
  if (pool) return true;
  apiError(res, 503, 'DATABASE_UNAVAILABLE', 'This service is temporarily unavailable.');
  return false;
};
const makeToken = user => jwt.sign({ sub: String(user.id), username: user.username, type: 'access', jti: crypto.randomUUID() }, config.jwtSecret, { expiresIn: `${config.sessionHours}h`, issuer: config.issuer, audience: config.audience });
const attempts = new Map();
const rateLimit = (windowMs, max) => (req, res, next) => { const key = `${req.path}:${req.ip}`, now = Date.now(), item = attempts.get(key) || { count: 0, reset: now + windowMs }; if (item.reset <= now) { item.count = 0; item.reset = now + windowMs; } item.count += 1; attempts.set(key, item); if (item.count > max) return apiError(res, 429, 'RATE_LIMITED', 'Too many requests. Please try again later.'); next(); };
const requireAuth = async (req, res, next) => {
  const token = req.headers.authorization?.match(/^Bearer ([A-Za-z0-9._-]+)$/)?.[1] || getCookie(req, 'session');
  if (!token) return apiError(res, 401, 'AUTH_REQUIRED', 'Please log in first.');
  try { const claims = jwt.verify(token, config.jwtSecret, { issuer: config.issuer, audience: config.audience }); if (claims.type !== 'access') throw new Error('invalid'); if (pool && (await pool.query('SELECT 1 FROM revoked_tokens WHERE jti=$1 AND expires_at>NOW()', [claims.jti])).rowCount) throw new Error('revoked'); req.user = { id: parseId(claims.sub), username: claims.username, jti: claims.jti }; next(); }
  catch { audit(req, 'authentication.failed', { result: 'denied' }); apiError(res, 401, 'INVALID_SESSION', 'Your session has expired. Please log in again.'); }
};
app.post('/api/auth/register', rateLimit(15 * 60 * 1000, 10), async (req, res) => {
  if (!requireDatabase(res)) return;
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  if (!/^[a-zA-Z0-9_]{3,40}$/.test(username)) return res.status(400).json({ error: 'Use 3–40 letters, numbers, or underscores for your username.' });
  if (password.length < 10 || password.length > 128 || !/[A-Za-z]/.test(password) || !/\d/.test(password)) return apiError(res, 400, 'WEAK_PASSWORD', 'Use a password of at least 10 characters with letters and numbers.');
  try {
    const existing = await pool.query('SELECT 1 FROM users WHERE LOWER(username)=LOWER($1) AND deleted_at IS NULL', [username]);
    if (existing.rowCount) return apiError(res, 409, 'USERNAME_TAKEN', 'That username is already taken.');
    const passwordHash = await bcrypt.hash(password, 12);
    const result = await pool.query('INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username, avatar_url, whatsapp, created_at', [username, passwordHash]);
    const user = result.rows[0];
    const csrfToken = setSession(res, user);
    audit(req, 'account.registered', { resourceType: 'user', resourceId: user.id });
    res.status(201).json({ user, csrfToken });
  } catch (error) {
    if (error.code === '23505') return res.status(409).json({ error: 'That username is already taken.' });
    console.error(error); res.status(500).json({ error: 'Could not create account.' });
  }
});
app.post('/api/auth/login', rateLimit(15 * 60 * 1000, 10), async (req, res) => {
  if (!requireDatabase(res)) return;
  const username = String(req.body.username || '').trim();
  const result = await pool.query('SELECT id, username, avatar_url, whatsapp, created_at, password_hash FROM users WHERE username = $1 AND deleted_at IS NULL', [username]);
  const user = result.rows[0];
  if (!user || !(await bcrypt.compare(String(req.body.password || ''), user.password_hash))) return res.status(401).json({ error: 'Incorrect username or password.' });
  delete user.password_hash;
  const csrfToken = setSession(res, user);
  audit(req, 'authentication.succeeded', { resourceType: 'user', resourceId: user.id });
  res.json({ user, csrfToken });
});
app.post('/api/auth/logout', requireAuth, csrf, async (req, res, next) => {
  try {
    if (pool) await pool.query("INSERT INTO revoked_tokens (jti,expires_at) VALUES ($1,NOW() + ($2 || ' hours')::interval) ON CONFLICT DO NOTHING", [req.user.jti, config.sessionHours]);
    res.clearCookie('session', { path: '/' }); res.clearCookie('csrf', { path: '/' }); audit(req, 'authentication.logout'); res.status(204).end();
  } catch (error) { next(error); }
});
app.get('/api/listings', async (req, res) => {
  if (!pool) return res.json([]);
  const { q = '', category = '', min, max } = req.query;
  const values = [`%${q}%`];
  let where = "WHERE l.sold = false AND (l.title ILIKE $1 OR l.color ILIKE $1 OR l.category ILIKE $1)";
  if (category) { values.push(category); where += ` AND l.category = $${values.length}`; }
  if (min) { values.push(min); where += ` AND l.price_zmw >= $${values.length}`; }
  if (max) { values.push(max); where += ` AND l.price_zmw <= $${values.length}`; }
  const result = await pool.query(`SELECT l.*, u.username, u.avatar_url, u.whatsapp FROM listings l JOIN users u ON u.id=l.seller_id ${where} ORDER BY l.created_at DESC`, values);
  res.json(result.rows);
});
app.post('/api/listings', requireAuth, csrf, async (req, res) => {
  if (!requireDatabase(res)) return;
  const { title, price, description = '', category, color = '', size = '', images = [] } = req.body;
  const validCategories = ['Shirts', 'Jerseys', 'Sneakers', 'Hoodies', 'Pants'];
  if (!String(title || '').trim() || !validCategories.includes(category)) return res.status(400).json({ error: 'Please add a title and choose a category.' });
  if (!Number.isFinite(Number(price)) || Number(price) <= 0) return res.status(400).json({ error: 'Enter a valid price in ZMW.' });
  if (!Array.isArray(images) || images.length < 1 || images.length > 7) return res.status(400).json({ error: 'Add at least one photo, with a maximum of 7.' });
  const result = await pool.query(
    'INSERT INTO listings (seller_id, title, price_zmw, description, category, color, size, images) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
    [req.user.id, title.trim(), price, description.trim(), category, color.trim(), size.trim(), JSON.stringify(images)]
  );
  res.status(201).json(result.rows[0]);
});
app.get('/api/me', requireAuth, async (req, res) => {
  if (!requireDatabase(res)) return;
  const user = await pool.query('SELECT id, username, avatar_url, whatsapp, created_at FROM users WHERE id=$1', [req.user.id]);
  const sales = await pool.query('SELECT COALESCE(SUM(price_zmw),0) AS total_sales, COUNT(*) FILTER (WHERE sold) AS sold_count, COUNT(*) FILTER (WHERE NOT sold) AS available_count FROM listings WHERE seller_id=$1', [req.user.id]);
  res.json({ user: user.rows[0], stats: sales.rows[0] });
});
app.put('/api/me', requireAuth, csrf, async (req, res) => {
  if (!requireDatabase(res)) return;
  const whatsapp = String(req.body.whatsapp || '').trim();
  const avatarUrl = String(req.body.avatar_url || '').trim() || null;
  if (whatsapp && !/^[+0-9 ()-]{7,25}$/.test(whatsapp)) return res.status(400).json({ error: 'Enter a valid WhatsApp number.' });
  const result = await pool.query('UPDATE users SET whatsapp=$1, avatar_url=$2 WHERE id=$3 RETURNING id, username, avatar_url, whatsapp, created_at', [whatsapp || null, avatarUrl, req.user.id]);
  res.json(result.rows[0]);
});
app.get('/api/me/listings', requireAuth, async (req, res) => {
  if (!requireDatabase(res)) return;
  const result = await pool.query('SELECT * FROM listings WHERE seller_id=$1 ORDER BY created_at DESC', [req.user.id]);
  res.json(result.rows);
});
app.put('/api/listings/:id', requireAuth, csrf, async (req, res) => {
  if (!requireDatabase(res)) return;
  const { title, price, description, color, size, images } = req.body;
  const values = [req.params.id, req.user.id];
  const ownership = await pool.query('SELECT id FROM listings WHERE id=$1 AND seller_id=$2', values);
  if (!ownership.rowCount) return res.status(404).json({ error: 'Listing not found.' });
  if (price !== undefined && (!Number.isFinite(Number(price)) || Number(price) <= 0)) return res.status(400).json({ error: 'Enter a valid price.' });
  if (images && (!Array.isArray(images) || images.length < 1 || images.length > 7)) return res.status(400).json({ error: 'Use between 1 and 7 photos.' });
  const result = await pool.query('UPDATE listings SET title=COALESCE($1,title), price_zmw=COALESCE($2,price_zmw), description=COALESCE($3,description), color=COALESCE($4,color), size=COALESCE($5,size), images=COALESCE($6,images) WHERE id=$7 AND seller_id=$8 RETURNING *', [title?.trim() || null, price ?? null, description?.trim() || null, color?.trim() || null, size?.trim() || null, images ? JSON.stringify(images) : null, req.params.id, req.user.id]);
  res.json(result.rows[0]);
});
app.delete('/api/listings/:id', requireAuth, csrf, async (req, res) => {
  if (!requireDatabase(res)) return;
  const result = await pool.query('DELETE FROM listings WHERE id=$1 AND seller_id=$2 RETURNING id', [req.params.id, req.user.id]);
  if (!result.rowCount) return res.status(404).json({ error: 'Listing not found.' });
  res.status(204).end();
});
app.patch('/api/listings/:id/status', requireAuth, csrf, async (req, res) => {
  if (!requireDatabase(res)) return;
  let buyerId = null;
  if (req.body.sold && req.body.buyerUsername) {
    const buyer = await pool.query('SELECT id FROM users WHERE username=$1', [String(req.body.buyerUsername).trim()]);
    if (!buyer.rowCount) return res.status(400).json({ error: 'Buyer username was not found.' });
    buyerId = buyer.rows[0].id;
  }
  const result = await pool.query('UPDATE listings SET sold=$1, buyer_id=$2 WHERE id=$3 AND seller_id=$4 RETURNING *', [Boolean(req.body.sold), buyerId, req.params.id, req.user.id]);
  if (!result.rowCount) return res.status(404).json({ error: 'Listing not found.' });
  res.json(result.rows[0]);
});
app.get('/api/favorites', requireAuth, async (req, res) => {
  if (!requireDatabase(res)) return;
  const result = await pool.query('SELECT l.*, u.username, u.avatar_url, u.whatsapp FROM favorites f JOIN listings l ON l.id=f.listing_id JOIN users u ON u.id=l.seller_id WHERE f.user_id=$1 ORDER BY f.created_at DESC', [req.user.id]);
  res.json(result.rows);
});
app.post('/api/favorites/:listingId', requireAuth, csrf, async (req, res) => {
  if (!requireDatabase(res)) return;
  await pool.query('INSERT INTO favorites (user_id,listing_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [req.user.id, req.params.listingId]);
  res.status(201).end();
});
app.delete('/api/favorites/:listingId', requireAuth, csrf, async (req, res) => {
  if (!requireDatabase(res)) return;
  await pool.query('DELETE FROM favorites WHERE user_id=$1 AND listing_id=$2', [req.user.id, req.params.listingId]);
  res.status(204).end();
});
app.get('/api/sellers/:id', async (req, res) => {
  if (!requireDatabase(res)) return;
  const seller = await pool.query('SELECT id, username, avatar_url, whatsapp, created_at FROM users WHERE id=$1', [req.params.id]);
  if (!seller.rowCount) return res.status(404).json({ error: 'Seller not found.' });
  const stats = await pool.query('SELECT COUNT(*) AS listings, COALESCE(ROUND(AVG(stars),1),0) AS rating, COUNT(r.id) AS reviews FROM listings l LEFT JOIN reviews r ON r.seller_id=l.seller_id WHERE l.seller_id=$1 GROUP BY l.seller_id', [req.params.id]);
  res.json({ ...seller.rows[0], stats: stats.rows[0] || { listings: 0, rating: 0, reviews: 0 } });
});
app.get('/api/sellers/:id/listings', async (req, res) => {
  if (!requireDatabase(res)) return;
  const result = await pool.query('SELECT * FROM listings WHERE seller_id=$1 AND sold=false ORDER BY created_at DESC', [req.params.id]);
  res.json(result.rows);
});
app.get('/api/sellers/:id/reviews', async (req, res) => {
  if (!requireDatabase(res)) return;
  const result = await pool.query('SELECT r.*, u.username AS reviewer FROM reviews r LEFT JOIN users u ON u.id=r.reviewer_id WHERE r.seller_id=$1 ORDER BY r.created_at DESC', [req.params.id]);
  res.json(result.rows);
});
app.post('/api/sellers/:id/reviews', requireAuth, csrf, async (req, res) => {
  if (!requireDatabase(res)) return;
  const stars = Number(req.body.stars), body = String(req.body.body || '').trim();
  if (!Number.isInteger(stars) || stars < 1 || stars > 5) return res.status(400).json({ error: 'Choose a rating from 1 to 5.' });
  const sale = await pool.query('SELECT id FROM listings WHERE seller_id=$1 AND buyer_id=$2 AND sold=true LIMIT 1', [req.params.id, req.user.id]);
  if (!sale.rowCount) return res.status(403).json({ error: 'Only verified buyers can review this seller.' });
  await pool.query('INSERT INTO reviews (seller_id, reviewer_id, stars, body) VALUES ($1,$2,$3,$4)', [req.params.id, req.user.id, stars, body]);
  res.status(201).end();
});
app.get('/api/messages', requireAuth, async (req, res) => {
  if (!requireDatabase(res)) return;
  const result = await pool.query(`SELECT DISTINCT ON (partner_id) partner_id, partner_username, body, created_at, unread, listing_id, listing_title FROM (SELECT CASE WHEN m.sender_id=$1 THEN m.recipient_id ELSE m.sender_id END AS partner_id, CASE WHEN m.sender_id=$1 THEN ru.username ELSE su.username END AS partner_username, m.body, m.created_at, (m.recipient_id=$1 AND NOT m.read) AS unread, m.listing_id, l.title AS listing_title FROM messages m JOIN users su ON su.id=m.sender_id JOIN users ru ON ru.id=m.recipient_id LEFT JOIN listings l ON l.id=m.listing_id WHERE m.sender_id=$1 OR m.recipient_id=$1) x ORDER BY partner_id, created_at DESC`, [req.user.id]);
  res.json(result.rows);
});
app.get('/api/messages/:userId', requireAuth, async (req, res) => {
  if (!requireDatabase(res)) return;
  const result = await pool.query('SELECT m.*, l.title AS listing_title, l.price_zmw AS listing_price_zmw, l.images AS listing_images FROM messages m LEFT JOIN listings l ON l.id=m.listing_id WHERE (m.sender_id=$1 AND m.recipient_id=$2) OR (m.sender_id=$2 AND m.recipient_id=$1) ORDER BY m.created_at ASC', [req.user.id, req.params.userId]);
  await pool.query('UPDATE messages SET read=true WHERE sender_id=$1 AND recipient_id=$2', [req.params.userId, req.user.id]);
  res.json(result.rows);
});
app.post('/api/messages/:userId', requireAuth, csrf, async (req, res) => {
  if (!requireDatabase(res)) return;
  const body = String(req.body.body || '').trim();
  if (!body || body.length > 2000) return res.status(400).json({ error: 'Write a message up to 2,000 characters.' });
  const recipientId = parseId(req.params.userId, 'recipient ID');
  let listingId = null;
  if (req.body.listingId !== undefined && req.body.listingId !== null) {
    listingId = parseId(req.body.listingId, 'listing ID');
    const listing = await pool.query('SELECT seller_id FROM listings WHERE id=$1', [listingId]);
    if (!listing.rowCount || listing.rows[0].seller_id !== recipientId) return apiError(res, 400, 'INVALID_LISTING', 'This listing cannot be attached to that conversation.');
  }
  const result = await pool.query('INSERT INTO messages (sender_id, recipient_id, listing_id, body) VALUES ($1,$2,$3,$4) RETURNING *', [req.user.id, recipientId, listingId, body]);
  res.status(201).json(result.rows[0]);
});
app.get('/privacy', (_, res) => res.sendFile(path.join(__dirname, 'public', 'privacy.html')));
app.get('/favicon.ico', (_, res) => res.type('image/svg+xml').sendFile(path.join(__dirname, 'public', 'favicon.svg')));
app.get('*', (_, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.use((error, req, res, next) => {
  if (error instanceof SyntaxError && 'body' in error) return apiError(res, 400, 'INVALID_JSON', 'Malformed JSON request.');
  console.error(JSON.stringify({ level: 'error', component: 'api', requestId: req.id, message: error.message }));
  return apiError(res, 400, 'INVALID_REQUEST', 'The request could not be processed.');
});
if (require.main === module) app.listen(process.env.PORT || 3000, () => console.log(JSON.stringify({ level: 'info', component: 'server', message: `Listening on port ${process.env.PORT || 3000}` })));
module.exports = { app, helpers: { parseId, plainText, validateImage, config } };
