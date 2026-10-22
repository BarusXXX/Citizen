import bcrypt from 'bcryptjs';
import { Writable } from 'node:stream';
import { createInterface } from 'node:readline/promises';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { openDatabase } from './database.js';

const here = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(here, '..');

export function administratorDatabaseFile() {
  const dataDirectory = resolve(process.env.CITIZEN_DATA_DIR || join(projectRoot, 'data'));
  return resolve(process.env.CITIZEN_DATABASE || join(dataDirectory, 'citizen.sqlite'));
}

export async function resetAdministrator({ databaseFile = administratorDatabaseFile(), adminName, password }) {
  const name = typeof adminName === 'string' ? adminName.trim() : '';
  if (!name || name.length > 80) throw new Error('Administrator name must contain 1–80 characters.');
  if (typeof password !== 'string' || password.length < 12 || password.length > 200) throw new Error('Administrator password must contain 12–200 characters.');
  if (!existsSync(databaseFile)) throw new Error(`No CITIZEN database was found at ${databaseFile}`);

  const store = openDatabase(databaseFile);
  try {
    if (!store.getSetting('admin_password_hash')) throw new Error('Administrator setup has not been completed for this database. Use the Admin page for first-time setup.');
    const passwordHash = await bcrypt.hash(password, 12);
    store.db.transaction(() => {
      store.setSetting('admin_name', name);
      store.setSetting('admin_password_hash', passwordHash);
      store.db.prepare('DELETE FROM admin_sessions').run();
    })();
    return { adminName: name, databaseFile };
  } finally {
    store.db.close();
  }
}

class HiddenOutput extends Writable {
  muted = false;
  _write(chunk, encoding, callback) {
    if (!this.muted) process.stdout.write(chunk, encoding);
    callback();
  }
}

async function hiddenQuestion(reader, output, prompt) {
  output.muted = true;
  process.stdout.write(prompt);
  try { return await reader.question(''); }
  finally { output.muted = false; process.stdout.write('\n'); }
}

async function main() {
  if (!process.stdin.isTTY) throw new Error('Run this command in an interactive terminal on the server computer.');
  const output = new HiddenOutput();
  const reader = createInterface({ input: process.stdin, output, terminal: true });
  try {
    console.log('CITIZEN administrator reset');
    console.log(`Database: ${administratorDatabaseFile()}`);
    console.log('Collections, devices and sessions will be preserved. Existing admin sign-ins will be invalidated.\n');
    const adminName = await reader.question('New administrator name: ');
    const password = await hiddenQuestion(reader, output, 'New password (12 or more characters): ');
    const confirmation = await hiddenQuestion(reader, output, 'Confirm new password: ');
    if (password !== confirmation) throw new Error('The passwords do not match. Nothing was changed.');
    const result = await resetAdministrator({ adminName, password });
    console.log(`Administrator reset complete for ${result.adminName}.`);
    console.log('Start CITIZEN and sign in with the new password.');
  } finally {
    reader.close();
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(`Reset failed: ${error.message}`); process.exitCode = 1; });
}
