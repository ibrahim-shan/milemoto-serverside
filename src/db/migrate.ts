import { promises as fs } from 'fs';
import { join, resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { pool } from './pool.js';
import { logger } from '../utils/logger.js';
import type { RowDataPacket } from 'mysql2/promise';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const MIGRATIONS_DIR = resolve(__dirname, '../../migrations');

type Quote = "'" | '"' | '`';

async function ensureMigrationsTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS _migrations (
      id INT PRIMARY KEY AUTO_INCREMENT,
      name VARCHAR(255) NOT NULL UNIQUE,
      applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);
}

async function appliedSet(): Promise<Set<string>> {
  const [rows] = await pool.query<RowDataPacket[]>('SELECT name FROM _migrations ORDER BY id');
  return new Set(rows.map((r) => r.name as string));
}

// robust splitter (handles quotes and comments)
function splitSql(sql: string): string[] {
  const s = sql.replace(/\r\n/g, '\n').replace(/\/\*[\s\S]*?\*\//g, '');
  const out: string[] = [];
  let buf = '';
  let quote: Quote | null = null;
  let esc = false;

  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    const next2 = s.slice(i, i + 2);

    if (!quote && next2 === '--') {
      while (i < s.length && s[i] !== '\n') i++;
      buf += '\n';
      continue;
    }

    if (quote) {
      buf += ch;
      if (esc) {
        esc = false;
        continue;
      }
      if (ch === '\\') {
        esc = true;
        continue;
      }
      if (ch === quote) quote = null;
      continue;
    }

    if (ch === "'" || ch === '"' || ch === '`') {
      quote = ch as Quote;
      buf += ch;
      continue;
    }

    if (ch === ';') {
      const stmt = buf.trim();
      if (stmt) out.push(stmt);
      buf = '';
      continue;
    }

    buf += ch;
  }
  const tail = buf.trim();
  if (tail) out.push(tail);
  return out.filter(Boolean);
}

async function runFile(filename: string) {
  const full = join(MIGRATIONS_DIR, filename);
  const sql = await fs.readFile(full, 'utf8');
  const stmts = splitSql(sql);

  const conn = await pool.getConnection();
  try {
    const [dbrow] = await conn.query<RowDataPacket[]>('SELECT DATABASE() AS db');
    console.log('RUN:', filename, '| DB=', dbrow[0]?.db, '| statements=', stmts.length);

    await conn.beginTransaction();
    for (let i = 0; i < stmts.length; i++) {
      const stmt = stmts[i];
      try {
        // short preview
        console.log(`  [${i + 1}/${stmts.length}]`, stmt.slice(0, 100).replace(/\s+/g, ' '), '...');
        await conn.query(stmt);
      } catch (err) {
        console.error('  FAILED stmt index', i, 'file', filename);
        console.error(stmt);
        throw err;
      }
    }
    await conn.query('INSERT INTO _migrations (name) VALUES (?)', [filename]);
    await conn.commit();
    logger.info({ migration: filename, statements: stmts.length }, 'applied');
  } catch (err) {
    await conn.rollback();
    logger.error({ migration: filename, err }, 'failed');
    throw err;
  } finally {
    conn.release();
  }
}

async function run() {
  console.log('--- MIGRATE START ---');
  console.log('CWD=', process.cwd());
  console.log('MIGRATIONS_DIR=', MIGRATIONS_DIR);

  await fs.mkdir(MIGRATIONS_DIR, { recursive: true });
  await ensureMigrationsTable();

  let files = await fs.readdir(MIGRATIONS_DIR);
  files = files.filter((f) => f.toLowerCase().endsWith('.sql')).sort();
  console.log('FILES_FOUND=', files);

  const done = await appliedSet();
  for (const f of files) {
    if (done.has(f)) {
      console.log('SKIP already applied:', f);
      continue;
    }
    await runFile(f);
  }
  console.log('--- MIGRATIONS COMPLETE ---');
}

run()
  .then(() => process.exit(0))
  .catch(() => process.exit(1));
