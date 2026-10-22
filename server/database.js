import Database from 'better-sqlite3';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export const sha256 = value => createHash('sha256').update(value).digest('hex');
export const randomToken = (bytes = 32) => randomBytes(bytes).toString('base64url');

export function openDatabase(filename) {
  mkdirSync(dirname(filename), { recursive: true });
  const db = new Database(filename);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 5000');
  db.exec(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS admin_sessions (
      token_hash TEXT PRIMARY KEY,
      csrf_token TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS collections (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      event_date TEXT,
      join_code_hash TEXT NOT NULL,
      sync_generation INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL,
      archived_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS devices (
      id TEXT PRIMARY KEY,
      collection_id TEXT NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
      label TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      created_at INTEGER NOT NULL,
      last_seen_at INTEGER NOT NULL,
      last_sync_generation INTEGER NOT NULL DEFAULT -1,
      revoked_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      collection_id TEXT NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
      device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
      source_namespace TEXT NOT NULL,
      source_session_id TEXT NOT NULL,
      title TEXT NOT NULL,
      schema_version INTEGER NOT NULL,
      background_type TEXT NOT NULL,
      object_count INTEGER NOT NULL,
      client_created_at INTEGER NOT NULL,
      client_updated_at INTEGER NOT NULL,
      received_at INTEGER NOT NULL,
      content_hash TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      UNIQUE(collection_id, source_namespace, source_session_id)
    );
    CREATE INDEX IF NOT EXISTS sessions_collection_updated ON sessions(collection_id, client_updated_at DESC);
    CREATE INDEX IF NOT EXISTS sessions_device ON sessions(device_id);
  `);

  const getSettingStatement = db.prepare('SELECT value FROM settings WHERE key = ?');
  const setSettingStatement = db.prepare('INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value');
  const getSetting = key => getSettingStatement.get(key)?.value;
  const setSetting = (key, value) => setSettingStatement.run(key, String(value));
  if (!getSetting('server_secret')) setSetting('server_secret', randomToken(48));

  const mergeSession = db.transaction(({ collectionId, deviceId = null, sourceNamespace, sourceSessionId, session, payloadJson }) => {
    const contentHash = sha256(payloadJson);
    const existing = db.prepare(`SELECT * FROM sessions
      WHERE collection_id = ? AND source_namespace = ? AND source_session_id = ?`).get(collectionId, sourceNamespace, sourceSessionId);
    const now = Date.now();
    if (existing?.content_hash === contentHash) return { status: 'unchanged', id: existing.id, contentHash };
    if (existing && session.updatedAt < existing.client_updated_at) return { status: 'skipped-older', id: existing.id, contentHash: existing.content_hash };
    if (existing && session.updatedAt === existing.client_updated_at) {
      const conflictId = randomUUID();
      const conflictSourceId = `${sourceSessionId}:conflict:${contentHash.slice(0, 12)}`;
      const duplicate = db.prepare(`SELECT id FROM sessions WHERE collection_id = ? AND source_namespace = ? AND source_session_id = ?`).get(collectionId, sourceNamespace, conflictSourceId);
      if (duplicate) return { status: 'unchanged', id: duplicate.id, contentHash };
      insertSession(db, { id: conflictId, collectionId, deviceId, sourceNamespace, sourceSessionId: conflictSourceId, session, payloadJson, contentHash, receivedAt: now });
      return { status: 'conflict', id: conflictId, contentHash };
    }
    if (existing) {
      db.prepare(`UPDATE sessions SET device_id = ?, title = ?, schema_version = ?, background_type = ?, object_count = ?,
        client_created_at = ?, client_updated_at = ?, received_at = ?, content_hash = ?, payload_json = ? WHERE id = ?`)
        .run(deviceId, session.title, session.version, session.background.type, session.objects.length,
          session.createdAt, session.updatedAt, now, contentHash, payloadJson, existing.id);
      return { status: 'updated', id: existing.id, contentHash };
    }
    const id = randomUUID();
    insertSession(db, { id, collectionId, deviceId, sourceNamespace, sourceSessionId, session, payloadJson, contentHash, receivedAt: now });
    return { status: 'created', id, contentHash };
  });

  return { db, getSetting, setSetting, mergeSession };
}

function insertSession(db, record) {
  const { id, collectionId, deviceId, sourceNamespace, sourceSessionId, session, payloadJson, contentHash, receivedAt } = record;
  db.prepare(`INSERT INTO sessions(id, collection_id, device_id, source_namespace, source_session_id, title, schema_version,
    background_type, object_count, client_created_at, client_updated_at, received_at, content_hash, payload_json)
    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(id, collectionId, deviceId, sourceNamespace, sourceSessionId, session.title, session.version,
      session.background.type, session.objects.length, session.createdAt, session.updatedAt, receivedAt, contentHash, payloadJson);
}

export function sessionMetadata(row) {
  return {
    id: row.id,
    collectionId: row.collection_id,
    deviceId: row.device_id,
    deviceName: row.device_label || null,
    collectionName: row.collection_name,
    sourceNamespace: row.source_namespace,
    sourceSessionId: row.source_session_id,
    title: row.title,
    version: row.schema_version,
    backgroundType: row.background_type,
    objectCount: row.object_count,
    createdAt: row.client_created_at,
    updatedAt: row.client_updated_at,
    receivedAt: row.received_at,
    contentHash: row.content_hash,
  };
}
