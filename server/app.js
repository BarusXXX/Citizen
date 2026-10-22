import express from 'express';
import bcrypt from 'bcryptjs';
import multer from 'multer';
import { ZipArchive } from 'archiver';
import { Open as openZip } from 'unzipper';
import { existsSync, mkdirSync, readFileSync, unlinkSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, posix, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { openDatabase, randomToken, sessionMetadata, sha256 } from './database.js';
import { validateSession } from '../src/session-format.js';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const dataDirectory = resolve(process.env.CITIZEN_DATA_DIR || join(root, 'data'));
const databaseFile = process.env.CITIZEN_DATABASE || join(dataDirectory, 'citizen.sqlite');
const uploadDirectory = join(dataDirectory, 'uploads');

export function createApp(options = {}) {
  const uploads = options.uploadDirectory || uploadDirectory;
  mkdirSync(uploads, { recursive: true });
  const store = options.store || openDatabase(options.databaseFile || databaseFile);
  const { db, getSetting, setSetting, mergeSession } = store;
  const app = express();
  app.disable('x-powered-by');
  if (process.env.CITIZEN_TRUST_PROXY === '1') app.set('trust proxy', 'loopback');
  options.configureApp?.(app);
  app.use(express.json({ limit: '31mb' }));

  const upload = multer({
    dest: uploads,
    limits: { files: 5000, fileSize: Number(process.env.CITIZEN_MAX_ARCHIVE_BYTES || 2_000_000_000) },
  });
  const loginLimiter = createRateLimiter(10, 15 * 60_000);
  const enrollLimiter = createRateLimiter(30, 15 * 60_000);

  const adminSession = request => {
    const token = cookies(request).citizen_admin;
    if (!token) return null;
    const row = db.prepare('SELECT * FROM admin_sessions WHERE token_hash = ? AND expires_at > ?').get(sha256(token), Date.now());
    return row ? { token, ...row } : null;
  };
  const deviceSession = request => {
    const token = cookies(request).citizen_device;
    if (!token) return null;
    return db.prepare(`SELECT d.*, c.name collection_name, c.sync_generation, c.archived_at
      FROM devices d JOIN collections c ON c.id = d.collection_id
      WHERE d.token_hash = ? AND d.revoked_at IS NULL`).get(sha256(token));
  };
  const requireAdmin = (request, response, next) => {
    const session = adminSession(request);
    if (!session) return response.status(401).json({ error: 'Administrator sign-in required.' });
    request.adminSession = session;
    next();
  };
  const requireAdminMutation = [requireAdmin, (request, response, next) => {
    if (!sameOrigin(request)) return response.status(403).json({ error: 'Invalid request origin.' });
    if (request.get('x-csrf-token') !== request.adminSession.csrf_token) return response.status(403).json({ error: 'Invalid security token.' });
    next();
  }];
  const requireDevice = (request, response, next) => {
    const device = deviceSession(request);
    if (!device) return response.status(401).json({ error: 'This browser is not enrolled.' });
    request.device = device;
    db.prepare('UPDATE devices SET last_seen_at = ? WHERE id = ?').run(Date.now(), device.id);
    next();
  };

  const extension = options.installExtension?.(app, { db, dataDirectory: options.dataDirectory || dirname(options.databaseFile || databaseFile), requireAdmin, requireAdminMutation, upload, readZip });

  app.get('/api/v1/admin/status', (request, response) => {
    const configured = Boolean(getSetting('admin_password_hash'));
    const session = adminSession(request);
    response.json({ configured, authenticated: Boolean(session), adminName: configured ? getSetting('admin_name') || 'Administrator' : null, csrfToken: session?.csrf_token || null, setupAllowed: !configured && isLoopback(request) });
  });

  app.post('/api/v1/admin/setup', loginLimiter, async (request, response) => {
    if (getSetting('admin_password_hash')) return response.status(409).json({ error: 'Administrator setup is already complete.' });
    if (!isLoopback(request)) return response.status(403).json({ error: 'First-time setup must be completed on the server computer.' });
    if (!sameOrigin(request)) return response.status(403).json({ error: 'Invalid request origin.' });
    const adminName = cleanText(request.body?.adminName, 80);
    const password = request.body?.password;
    if (!adminName) return response.status(400).json({ error: 'Enter an administrator name.' });
    if (typeof password !== 'string' || password.length < 12 || password.length > 200) return response.status(400).json({ error: 'Use an administrator password of at least 12 characters.' });
    setSetting('admin_password_hash', await bcrypt.hash(password, 12));
    setSetting('admin_name', adminName);
    response.status(201).json(issueAdminSession(db, response, adminName));
  });

  app.post('/api/v1/admin/login', loginLimiter, async (request, response) => {
    if (!sameOrigin(request)) return response.status(403).json({ error: 'Invalid request origin.' });
    const hash = getSetting('admin_password_hash');
    if (!hash || typeof request.body?.password !== 'string' || !(await bcrypt.compare(request.body.password, hash))) {
      return response.status(401).json({ error: 'Incorrect administrator password.' });
    }
    response.json(issueAdminSession(db, response, getSetting('admin_name') || 'Administrator'));
  });

  app.post('/api/v1/admin/logout', ...requireAdminMutation, (request, response) => {
    extension?.onAdminLogout?.(request.adminSession);
    db.prepare('DELETE FROM admin_sessions WHERE token_hash = ?').run(sha256(request.adminSession.token));
    clearCookie(response, 'citizen_admin');
    response.json({ ok: true });
  });

  app.get('/api/v1/admin/collections', requireAdmin, (request, response) => {
    const rows = db.prepare(`SELECT c.*,
      (SELECT COUNT(*) FROM devices d WHERE d.collection_id = c.id AND d.revoked_at IS NULL) device_count,
      (SELECT COUNT(*) FROM sessions s WHERE s.collection_id = c.id) session_count
      FROM collections c ORDER BY c.created_at DESC`).all();
    response.json(rows.map(collectionJson));
  });

  app.post('/api/v1/admin/collections', ...requireAdminMutation, async (request, response) => {
    const name = cleanText(request.body?.name, 100);
    const eventDate = request.body?.eventDate || null;
    if (!name || (eventDate && !/^\d{4}-\d{2}-\d{2}$/.test(eventDate))) return response.status(400).json({ error: 'Enter a valid collection name and date.' });
    const id = randomUUID(), joinCode = makeJoinCode();
    db.prepare('INSERT INTO collections(id, name, event_date, join_code_hash, created_at) VALUES(?, ?, ?, ?, ?)')
      .run(id, name, eventDate, await bcrypt.hash(joinCode, 10), Date.now());
    response.status(201).json({ ...collectionJson(db.prepare('SELECT *, 0 device_count, 0 session_count FROM collections WHERE id = ?').get(id)), joinCode });
  });

  app.post('/api/v1/admin/collections/:id/join-code', ...requireAdminMutation, async (request, response) => {
    const collection = db.prepare('SELECT * FROM collections WHERE id = ?').get(request.params.id);
    if (!collection) return response.status(404).json({ error: 'Collection not found.' });
    if (collection.archived_at) return response.status(409).json({ error: 'Archived collections cannot accept new devices.' });
    const joinCode = makeJoinCode();
    db.prepare('UPDATE collections SET join_code_hash = ? WHERE id = ?').run(await bcrypt.hash(joinCode, 10), collection.id);
    response.json({ joinCode });
  });

  app.post('/api/v1/admin/collections/:id/archive', ...requireAdminMutation, (request, response) => {
    const archivedAt = request.body?.archived === false ? null : Date.now();
    const result = db.prepare('UPDATE collections SET archived_at = ? WHERE id = ?').run(archivedAt, request.params.id);
    if (!result.changes) return response.status(404).json({ error: 'Collection not found.' });
    response.json({ archived: Boolean(archivedAt) });
  });

  app.post('/api/v1/admin/collections/:id/request-sync', ...requireAdminMutation, (request, response) => {
    const result = db.prepare('UPDATE collections SET sync_generation = sync_generation + 1 WHERE id = ? AND archived_at IS NULL').run(request.params.id);
    if (!result.changes) return response.status(404).json({ error: 'Active collection not found.' });
    const generation = db.prepare('SELECT sync_generation FROM collections WHERE id = ?').get(request.params.id).sync_generation;
    response.json({ syncGeneration: generation });
  });

  app.get('/api/v1/admin/devices', requireAdmin, (request, response) => {
    const collectionId = request.query.collectionId;
    const rows = collectionId
      ? db.prepare('SELECT id, collection_id, label, created_at, last_seen_at, last_sync_generation, revoked_at FROM devices WHERE collection_id = ? ORDER BY label').all(collectionId)
      : db.prepare('SELECT id, collection_id, label, created_at, last_seen_at, last_sync_generation, revoked_at FROM devices ORDER BY label').all();
    response.json(rows.map(deviceJson));
  });

  app.post('/api/v1/admin/devices/:id/revoke', ...requireAdminMutation, (request, response) => {
    const result = db.prepare('UPDATE devices SET revoked_at = ? WHERE id = ?').run(Date.now(), request.params.id);
    if (!result.changes) return response.status(404).json({ error: 'Device not found.' });
    response.json({ ok: true });
  });

  app.get('/api/v1/admin/sessions', requireAdmin, (request, response) => {
    const clauses = [], values = [];
    if (request.query.collectionId) { clauses.push('s.collection_id = ?'); values.push(request.query.collectionId); }
    if (request.query.deviceId) { clauses.push('s.device_id = ?'); values.push(request.query.deviceId); }
    if (request.query.backgroundType) { clauses.push('s.background_type = ?'); values.push(request.query.backgroundType); }
    if (request.query.q) { clauses.push('LOWER(s.title) LIKE ?'); values.push(`%${String(request.query.q).toLowerCase().slice(0, 100)}%`); }
    if (request.query.from) { clauses.push('s.client_updated_at >= ?'); values.push(Number(request.query.from)); }
    if (request.query.to) { clauses.push('s.client_updated_at <= ?'); values.push(Number(request.query.to)); }
    if (request.query.backupStatus === 'recent') { clauses.push('s.received_at >= ?'); values.push(Date.now() - 86_400_000); }
    if (request.query.backupStatus === 'stale') { clauses.push('s.received_at < ?'); values.push(Date.now() - 86_400_000); }
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    const rows = db.prepare(`SELECT s.*, d.label device_label, c.name collection_name FROM sessions s
      LEFT JOIN devices d ON d.id = s.device_id JOIN collections c ON c.id = s.collection_id
      ${where} ORDER BY s.client_updated_at DESC LIMIT 5000`).all(...values);
    response.json(rows.map(sessionMetadata));
  });

  app.get('/api/v1/admin/sessions/:id/preview', requireAdmin, (request, response) => {
    const row = db.prepare('SELECT payload_json FROM sessions WHERE id = ?').get(request.params.id);
    if (!row) return response.status(404).json({ error: 'Session not found.' });
    const session = JSON.parse(row.payload_json);
    if (session.background?.type === 'image') session.background = { ...session.background, data: null };
    if (session.assets) for (const asset of Object.values(session.assets)) asset.source = '';
    session.notes = '';
    session.objects = session.objects.slice(0, 5000).map(object => ({ ...object, description: '' }));
    response.json(session);
  });

  app.get('/api/v1/admin/sessions/:id', requireAdmin, (request, response) => {
    const row = db.prepare(`SELECT s.*, d.label device_label, c.name collection_name FROM sessions s
      LEFT JOIN devices d ON d.id = s.device_id JOIN collections c ON c.id = s.collection_id WHERE s.id = ?`).get(request.params.id);
    if (!row) return response.status(404).json({ error: 'Session not found.' });
    response.json({ ...sessionMetadata(row), session: JSON.parse(row.payload_json) });
  });

  app.delete('/api/v1/admin/sessions/:id', ...requireAdminMutation, (request, response) => {
    const result = db.prepare('DELETE FROM sessions WHERE id = ?').run(request.params.id);
    if (!result.changes) return response.status(404).json({ error: 'Session not found.' });
    response.json({ ok: true });
  });

  app.get('/api/v1/admin/export', requireAdmin, (request, response, next) => {
    try { exportArchive(db, request.query.collectionId || null, response); }
    catch (error) { next(error); }
  });

  app.post('/api/v1/admin/import', ...requireAdminMutation, upload.array('files', 5000), async (request, response, next) => {
    const files = request.files || [];
    try {
      if (!files.length) return response.status(400).json({ error: 'Choose at least one JSON or ZIP file.' });
      const records = [];
      for (const file of files) {
        if (/\.zip$/i.test(file.originalname)) records.push(...await readZip(file.path));
        else records.push(readLooseJson(file.path, file.originalname, request.body?.collectionId));
      }
      if (records.length > Number(process.env.CITIZEN_MAX_ARCHIVE_SESSIONS || 5000)) throw new Error('The import contains too many sessions.');
      const results = importRecords(db, mergeSession, records);
      response.json(results);
    } catch (error) { next(error); }
    finally { for (const file of files) try { unlinkSync(file.path); } catch { /* already removed */ } }
  });

  app.post('/api/v1/client/enroll', enrollLimiter, async (request, response) => {
    if (!sameOrigin(request)) return response.status(403).json({ error: 'Invalid request origin.' });
    const code = String(request.body?.code || '').trim().toUpperCase();
    const deviceName = cleanText(request.body?.deviceName, 80);
    if (!code || !deviceName) return response.status(400).json({ error: 'Enter the workshop code and a device name.' });
    const collections = db.prepare('SELECT * FROM collections WHERE archived_at IS NULL').all();
    let collection = null;
    for (const candidate of collections) if (await bcrypt.compare(code, candidate.join_code_hash)) { collection = candidate; break; }
    if (!collection) return response.status(401).json({ error: 'The workshop code is invalid or archived.' });
    const id = randomUUID(), token = randomToken(), now = Date.now();
    db.prepare(`INSERT INTO devices(id, collection_id, label, token_hash, created_at, last_seen_at)
      VALUES(?, ?, ?, ?, ?, ?)`).run(id, collection.id, deviceName, sha256(token), now, now);
    setCookie(response, 'citizen_device', token, { maxAge: 365 * 24 * 60 * 60 });
    response.status(201).json({ enrolled: true, device: { id, name: deviceName }, collection: collectionJson(collection), syncGeneration: collection.sync_generation });
  });

  app.get('/api/v1/client/status', (request, response) => {
    const device = deviceSession(request);
    if (!device) return response.json({ enrolled: false });
    db.prepare('UPDATE devices SET last_seen_at = ? WHERE id = ?').run(Date.now(), device.id);
    response.json({ enrolled: true, device: deviceJson(device), collection: { id: device.collection_id, name: device.collection_name, archived: Boolean(device.archived_at) }, syncGeneration: device.sync_generation });
  });

  app.put('/api/v1/client/sessions/:localId', requireDevice, (request, response) => {
    if (request.device.archived_at) return response.status(409).json({ error: 'This workshop collection is archived.' });
    let session;
    try { session = validateSession(request.body, { requireId: true }); }
    catch (error) { return response.status(400).json({ error: error.message }); }
    if (session.id !== request.params.localId) return response.status(400).json({ error: 'The session ID does not match the request.' });
    const payloadJson = JSON.stringify(session);
    if (Buffer.byteLength(payloadJson) > 30_000_000) return response.status(413).json({ error: 'Session files must be smaller than 30 MB.' });
    const result = mergeSession({ collectionId: request.device.collection_id, deviceId: request.device.id, sourceNamespace: `device:${request.device.id}`, sourceSessionId: session.id, session, payloadJson });
    response.json(result);
  });

  app.post('/api/v1/client/sync-complete', requireDevice, (request, response) => {
    const generation = Number(request.body?.generation);
    if (!Number.isInteger(generation) || generation < 0 || generation > request.device.sync_generation) return response.status(400).json({ error: 'Invalid sync generation.' });
    db.prepare('UPDATE devices SET last_sync_generation = ?, last_seen_at = ? WHERE id = ?').run(generation, Date.now(), request.device.id);
    response.json({ ok: true });
  });

  app.post('/api/v1/client/disconnect', requireDevice, (request, response) => {
    db.prepare('UPDATE devices SET revoked_at = ? WHERE id = ?').run(Date.now(), request.device.id);
    clearCookie(response, 'citizen_device');
    response.json({ ok: true });
  });

  const dist = options.staticDirectory || join(root, 'dist');
  if (existsSync(dist)) app.use(express.static(dist, { index: 'index.html' }));

  app.use((error, request, response, next) => {
    if (response.headersSent) return next(error);
    if (extension?.onError?.(error, request, response)) return;
    const status = error instanceof multer.MulterError || /too (many|large)|smaller than|invalid|valid CITIZEN|archive/i.test(error.message) ? 400 : 500;
    if (status === 500) console.error(error);
    response.status(status).json({ error: status === 500 ? 'The server could not complete this request.' : error.message });
  });

  return { app, store };
}

function issueAdminSession(db, response, adminName) {
  const token = randomToken(), csrfToken = randomToken(24), expiresAt = Date.now() + 8 * 60 * 60_000;
  db.prepare('DELETE FROM admin_sessions WHERE expires_at <= ?').run(Date.now());
  db.prepare('INSERT INTO admin_sessions(token_hash, csrf_token, expires_at) VALUES(?, ?, ?)').run(sha256(token), csrfToken, expiresAt);
  setCookie(response, 'citizen_admin', token, { maxAge: 8 * 60 * 60 });
  return { authenticated: true, adminName, csrfToken };
}

function cookies(request) {
  return Object.fromEntries(String(request.headers.cookie || '').split(';').map(part => part.trim()).filter(Boolean).map(part => {
    const index = part.indexOf('=');
    return [decodeURIComponent(part.slice(0, index)), decodeURIComponent(part.slice(index + 1))];
  }));
}

function setCookie(response, name, value, { maxAge } = {}) {
  const secure = process.env.CITIZEN_SECURE_COOKIES === '1';
  response.append('Set-Cookie', `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Strict${secure ? '; Secure' : ''}${maxAge ? `; Max-Age=${maxAge}` : ''}`);
}

function clearCookie(response, name) { response.append('Set-Cookie', `${name}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`); }
function cleanText(value, maximum) { return typeof value === 'string' && value.trim() && value.trim().length <= maximum ? value.trim() : ''; }
function isLoopback(request) {
  const loopbacks = ['127.0.0.1', '::1', '::ffff:127.0.0.1'];
  if (!loopbacks.includes(request.socket.remoteAddress)) return false;
  const forwarded = request.get('x-forwarded-for')?.split(',')[0].trim();
  return !forwarded || loopbacks.includes(forwarded);
}
function sameOrigin(request) {
  const origin = request.get('origin');
  if (!origin) return true;
  try {
    const url = new URL(origin);
    const hosts = [request.get('host'), ...(request.get('x-forwarded-host') || '').split(',')]
      .map(value => value?.trim().toLowerCase()).filter(Boolean);
    if (hosts.includes(url.host.toLowerCase())) return true;
    // Sec-Fetch-Site is supplied by the browser and cannot be set by page JavaScript.
    // It remains reliable when a development or reverse proxy rewrites Host headers.
    if (request.get('sec-fetch-site') === 'same-origin') return true;
    return process.env.NODE_ENV !== 'production' && ['127.0.0.1:5173', 'localhost:5173'].includes(url.host.toLowerCase());
  } catch { return false; }
}

function createRateLimiter(limit, windowMs) {
  const attempts = new Map();
  return (request, response, next) => {
    const key = request.ip || request.socket.remoteAddress;
    const now = Date.now(), recent = (attempts.get(key) || []).filter(time => now - time < windowMs);
    if (recent.length >= limit) return response.status(429).json({ error: 'Too many attempts. Please wait and try again.' });
    recent.push(now); attempts.set(key, recent); next();
  };
}

function makeJoinCode() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789', bytes = Buffer.from(randomToken(12));
  return Array.from({ length: 8 }, (_, index) => alphabet[bytes[index] % alphabet.length]).join('');
}

function collectionJson(row) {
  return { id: row.id, name: row.name, eventDate: row.event_date || null, syncGeneration: row.sync_generation || 0, createdAt: row.created_at, archived: Boolean(row.archived_at), archivedAt: row.archived_at || null, deviceCount: row.device_count || 0, sessionCount: row.session_count || 0 };
}

function deviceJson(row) {
  return { id: row.id, collectionId: row.collection_id, name: row.label, createdAt: row.created_at, lastSeenAt: row.last_seen_at, lastSyncGeneration: row.last_sync_generation, revoked: Boolean(row.revoked_at) };
}

function safeName(value) { return String(value || 'session').normalize('NFKD').replace(/[^a-zA-Z0-9._ -]/g, '').replace(/\s+/g, '-').slice(0, 80) || 'session'; }

function exportArchive(db, collectionId, response) {
  const collections = collectionId ? db.prepare('SELECT * FROM collections WHERE id = ?').all(collectionId) : db.prepare('SELECT * FROM collections ORDER BY created_at').all();
  if (collectionId && !collections.length) { response.status(404).json({ error: 'Collection not found.' }); return; }
  const collectionIds = collections.map(collection => collection.id);
  const devices = collectionIds.flatMap(id => db.prepare('SELECT * FROM devices WHERE collection_id = ?').all(id));
  const sessions = collectionIds.flatMap(id => db.prepare('SELECT * FROM sessions WHERE collection_id = ? ORDER BY client_updated_at').all(id));
  const paths = new Map();
  for (const row of sessions) paths.set(row.id, `sessions/${safeName(collections.find(item => item.id === row.collection_id)?.name)}/${safeName(row.title)}--${row.id}.utopize.json`);
  const manifest = {
    format: 'citizen-session-archive', archiveVersion: 1, exportedAt: new Date().toISOString(),
    collections: collections.map(collectionJson), devices: devices.map(deviceJson),
    sessions: sessions.map(row => ({ ...sessionMetadata(row), path: paths.get(row.id) })),
  };
  const archive = new ZipArchive({ zlib: { level: 6 } });
  archive.on('error', error => response.destroy(error));
  response.setHeader('Content-Type', 'application/zip');
  response.setHeader('Content-Disposition', `attachment; filename="${collectionId ? safeName(collections[0].name) : 'citizen-all-sessions'}.zip"`);
  archive.pipe(response);
  archive.append(JSON.stringify(manifest, null, 2), { name: 'manifest.json' });
  for (const row of sessions) archive.append(row.payload_json, { name: paths.get(row.id) });
  archive.finalize();
}

async function readZip(filename) {
  const directory = await openZip.file(filename);
  const maximumBytes = Number(process.env.CITIZEN_MAX_ARCHIVE_BYTES || 2_000_000_000);
  const maximumEntries = Number(process.env.CITIZEN_MAX_ARCHIVE_ENTRIES || 5000);
  let total = 0;
  const files = new Map();
  if (directory.files.length > maximumEntries) throw new Error('The ZIP archive contains too many entries.');
  for (const entry of directory.files) {
    const path = entry.path.replace(/\\/g, '/');
    const normalized = posix.normalize(path);
    if (entry.type === 'SymbolicLink' || isAbsolute(path) || path.split('/').includes('..') || normalized.startsWith('../')) throw new Error('The ZIP archive contains an unsafe path.');
    if (entry.type !== 'File') continue;
    total += entry.uncompressedSize;
    if (total > maximumBytes) throw new Error('The ZIP archive is too large.');
    if (entry.uncompressedSize > 30_000_000 && path !== 'manifest.json') throw new Error('A session in the archive is larger than 30 MB.');
    files.set(path, await entry.buffer());
  }
  const manifestBuffer = files.get('manifest.json');
  if (!manifestBuffer) throw new Error('The ZIP archive has no manifest.json.');
  let manifest;
  try { manifest = JSON.parse(manifestBuffer.toString('utf8')); } catch { throw new Error('The archive manifest is invalid JSON.'); }
  if (manifest?.format !== 'citizen-session-archive' || manifest.archiveVersion !== 1 || !Array.isArray(manifest.collections) || !Array.isArray(manifest.sessions)) throw new Error('This is not a supported CITIZEN archive.');
  const collections = new Map(manifest.collections.map(collection => [collection.id, collection]));
  const devices = new Map((manifest.devices || []).map(device => [device.id, device]));
  return manifest.sessions.map(metadata => {
    const content = files.get(metadata.path);
    if (!content) throw new Error(`The archive is missing ${metadata.path}.`);
    let parsed;
    try { parsed = JSON.parse(content.toString('utf8')); } catch { throw new Error(`${metadata.path} is invalid JSON.`); }
    const session = validateSession(parsed, { requireId: true });
    const payloadJson = JSON.stringify(session);
    if (typeof metadata.contentHash !== 'string' || sha256(payloadJson) !== metadata.contentHash) throw new Error(`${metadata.path} does not match its manifest checksum.`);
    return { collection: collections.get(metadata.collectionId), device: metadata.deviceId ? devices.get(metadata.deviceId) : null, metadata, session, payloadJson, raw: content };
  });
}

function readLooseJson(filename, originalName, collectionId) {
  if (!collectionId) throw new Error('Choose a destination collection for loose JSON files.');
  let parsed;
  try { parsed = JSON.parse(readFileSync(filename, 'utf8')); } catch { throw new Error(`${basename(originalName)} is invalid JSON.`); }
  const session = validateSession(parsed, { requireId: true });
  return { collection: { id: collectionId }, device: null, metadata: { sourceNamespace: 'legacy-json', sourceSessionId: session.id }, session, payloadJson: JSON.stringify(session) };
}

function importRecords(db, mergeSession, records) {
  const collectionIds = new Set(db.prepare('SELECT id FROM collections').all().map(row => row.id));
  const importedDeviceIds = new Map();
  for (const record of records) if (!record.collection?.id || (!collectionIds.has(record.collection.id) && !record.collection.name)) throw new Error('An imported session has no valid collection.');
  const counts = { created: 0, updated: 0, unchanged: 0, skippedOlder: 0, conflicts: 0, total: records.length };
  db.transaction(() => {
    for (const record of records) {
      if (!collectionIds.has(record.collection.id)) {
        db.prepare(`INSERT INTO collections(id, name, event_date, join_code_hash, sync_generation, created_at, archived_at)
          VALUES(?, ?, ?, ?, ?, ?, ?)`).run(record.collection.id, cleanText(record.collection.name, 100) || 'Imported workshop', record.collection.eventDate || null,
          bcrypt.hashSync(randomToken(), 10), record.collection.syncGeneration || 0, record.collection.createdAt || Date.now(), Date.now());
        collectionIds.add(record.collection.id);
      }
      let deviceId = null;
      if (record.device?.id) {
        const deviceKey = `${record.collection.id}:${record.device.id}`;
        const existingDevice = db.prepare('SELECT id, collection_id FROM devices WHERE id = ?').get(record.device.id);
        deviceId = importedDeviceIds.get(deviceKey) || (existingDevice?.collection_id === record.collection.id ? existingDevice.id : existingDevice ? randomUUID() : record.device.id);
        if (!db.prepare('SELECT id FROM devices WHERE id = ?').get(deviceId)) db.prepare(`INSERT INTO devices(id, collection_id, label, token_hash, created_at, last_seen_at, last_sync_generation, revoked_at)
          VALUES(?, ?, ?, ?, ?, ?, ?, ?)`).run(deviceId, record.collection.id, cleanText(record.device.name, 80) || 'Imported device', sha256(randomToken()),
          record.device.createdAt || Date.now(), record.device.lastSeenAt || Date.now(), record.device.lastSyncGeneration ?? -1, Date.now());
        importedDeviceIds.set(deviceKey, deviceId);
      }
      const sourceNamespace = record.metadata.sourceNamespace || (deviceId ? `device:${deviceId}` : 'legacy-json');
      const sourceSessionId = record.metadata.sourceSessionId || record.session.id;
      const result = mergeSession({ collectionId: record.collection.id, deviceId, sourceNamespace, sourceSessionId, session: record.session, payloadJson: record.payloadJson });
      if (result.status === 'created') counts.created++;
      else if (result.status === 'updated') counts.updated++;
      else if (result.status === 'unchanged') counts.unchanged++;
      else if (result.status === 'skipped-older') counts.skippedOlder++;
      else if (result.status === 'conflict') counts.conflicts++;
    }
  })();
  return counts;
}
