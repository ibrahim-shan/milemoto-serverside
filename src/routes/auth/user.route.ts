// src/routes/auth/user.route.ts
import { Router } from 'express';
import { pool } from '../../db/pool.js';
import { verifyAccess } from '../../utils/jwt.js';
import { requireAuth } from '../../middleware/authz.js';
import { RowDataPacket } from 'mysql2';
import type { UserDto } from '@milemoto/types';
import { UpdateProfile } from './auth.helpers.js';

export const userAuth = Router();

/** GET /api/auth/me */
userAuth.get('/me', async (req, res) => {
  const authz = req.get('authorization') || '';
  const token = authz.startsWith('Bearer ') ? authz.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const { sub } = verifyAccess(token);
    const [rows] = await pool.query<RowDataPacket[]>(
      `SELECT id, full_name, email, phone, role, status, mfa_enabled FROM users WHERE id = ? LIMIT 1`,
      [sub]
    );
    const u = rows[0];
    if (!u) return res.status(404).json({ error: 'Not found' });
    res.json({
      id: String(u.id),
      fullName: u.full_name,
      email: u.email,
      phone: u.phone,
      role: u.role,
      status: u.status,
      mfaEnabled: Boolean(u.mfa_enabled),
    } as UserDto);
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
});

/** POST /api/auth/me/update - update full name and phone */
userAuth.post('/me/update', requireAuth, async (req, res, next) => {
  try {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    const userId = String(req.user.id);

    const body = UpdateProfile.parse(req.body);
    const phoneVal = body.phone === undefined ? undefined : body.phone; // allow explicit null

    const fields: string[] = ['full_name = ?'];
    const values: Array<string | null> = [body.fullName];
    if (phoneVal !== undefined) {
      fields.push('phone = ?');
      values.push(phoneVal);
    }
    values.push(userId);

    await pool.query(`UPDATE users SET ${fields.join(', ')} WHERE id = ?`, values as never);

    const [rows] = await pool.query<RowDataPacket[]>(
      `SELECT id, full_name, email, phone, role, status, mfa_enabled FROM users WHERE id = ? LIMIT 1`,
      [userId]
    );
    const u = rows[0];
    if (!u) return res.status(404).json({ error: 'Not found' });

    res.json({
      id: String(u.id),
      fullName: u.full_name,
      email: u.email,
      phone: u.phone,
      role: u.role,
      status: u.status,
      mfaEnabled: Boolean(u.mfa_enabled),
    } as UserDto);
  } catch (e) {
    return next(e);
  }
});
