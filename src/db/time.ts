// src/db/time.ts
import { pool } from './pool.js';
import type { RowDataPacket } from 'mysql2/promise';

type NowRow = RowDataPacket & { now: Date | string };

/** DB current time using server timezone */
export async function dbNow(): Promise<Date> {
  const [rows] = await pool.query<NowRow[]>('SELECT NOW() AS now');
  const first = rows[0];
  if (!first || !first.now) throw new Error('NOW() returned no row');
  return new Date(first.now);
}

/** Optional: UTC time if you want timezone-stable tokens */
export async function dbUtcNow(): Promise<Date> {
  const [rows] = await pool.query<NowRow[]>('SELECT UTC_TIMESTAMP() AS now');
  const first = rows[0];
  if (!first || !first.now) throw new Error('UTC_TIMESTAMP() returned no row');
  return new Date(first.now);
}
