// src/routes/auth/device.route.ts
import { Router } from 'express';
import { z } from 'zod';
import { pool } from '../../db/pool.js';
import { requireAuth } from '../../middleware/authz.js';
import { RowDataPacket } from 'mysql2';
import type { OkResponseDto } from '@milemoto/types';
import { revokeAllTrustedDevices } from './auth.helpers.js';
import { env } from '../../config/env.js';

export const deviceAuth = Router();

// ===== Trusted Devices: list and revoke =====
deviceAuth.get('/trusted-devices', requireAuth, async (req, res, next) => {
  try {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    const userId = String(req.user.id);

    const [rows] = await pool.query<RowDataPacket[]>(
      `SELECT id, user_id, user_agent, ip, created_at, last_used_at, expires_at, revoked_at
         FROM trusted_devices
        WHERE user_id = ?
        ORDER BY created_at DESC`,
      [userId]
    );

    const cookie = String(req.cookies?.mm_trusted || '');
    const currentId = cookie.includes('.') ? cookie.split('.')[0] : '';

    const devices = rows.map((d) => ({
      id: String(d.id),
      userAgent: d.user_agent as string | null,
      ip: d.ip as string | null,
      createdAt: d.created_at ? new Date(d.created_at).toISOString() : null,
      lastUsedAt: d.last_used_at ? new Date(d.last_used_at).toISOString() : null,
      expiresAt: d.expires_at ? new Date(d.expires_at).toISOString() : null,
      revokedAt: d.revoked_at ? new Date(d.revoked_at).toISOString() : null,
      current: String(d.id) === currentId,
    }));

    res.json({ items: devices });
  } catch (e) {
    next(e);
  }
});

deviceAuth.post('/trusted-devices/revoke', requireAuth, async (req, res, next) => {
  try {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    const userId = String(req.user.id);
    const { id } = z.object({ id: z.string().min(10) }).parse(req.body);

    const [rows] = await pool.query<RowDataPacket[]>(
      `SELECT id FROM trusted_devices WHERE id = ? AND user_id = ? AND revoked_at IS NULL LIMIT 1`,
      [id, userId]
    );
    const rec = rows[0];
    if (!rec) return res.status(404).json({ error: 'Not found' });

    await pool.query(`UPDATE trusted_devices SET revoked_at = NOW() WHERE id = ?`, [id]);

    const cookie = String(req.cookies?.mm_trusted || '');
    const currentId = cookie.includes('.') ? cookie.split('.')[0] : '';
    if (currentId === id) {
      res.clearCookie('mm_trusted', {
        path: '/',
        domain: env.COOKIE_DOMAIN || undefined,
        sameSite: 'lax',
        secure: env.NODE_ENV === 'production',
      });
    }
    await revokeAllTrustedDevices(String(userId));
    res.json({ ok: true } as OkResponseDto);
  } catch (e) {
    next(e);
  }
});

deviceAuth.post('/trusted-devices/revoke-all', requireAuth, async (req, res, next) => {
  try {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    const userId = String(req.user.id);

    await pool.query(
      `UPDATE trusted_devices SET revoked_at = NOW() WHERE user_id = ? AND revoked_at IS NULL`,
      [userId]
    );

    if (req.cookies?.mm_trusted) {
      res.clearCookie('mm_trusted', {
        path: '/',
        domain: env.COOKIE_DOMAIN || undefined,
        sameSite: 'lax',
        secure: env.NODE_ENV === 'production',
      });
    }
    await revokeAllTrustedDevices(String(userId));
    res.json({ ok: true } as OkResponseDto);
  } catch (e) {
    next(e);
  }
});

deviceAuth.post('/trusted-devices/untrust-current', requireAuth, async (req, res, next) => {
  try {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    const userId = String(req.user.id);
    const cookie = String(req.cookies?.mm_trusted || '');
    if (!cookie.includes('.')) return res.status(400).json({ error: 'No trusted device cookie' });
    const [id] = cookie.split('.');

    await pool.query(`UPDATE trusted_devices SET revoked_at = NOW() WHERE id = ? AND user_id = ?`, [
      id,
      userId,
    ]);
    res.clearCookie('mm_trusted', {
      path: '/',
      domain: env.COOKIE_DOMAIN || undefined,
      sameSite: 'lax',
      secure: env.NODE_ENV === 'production',
    });
    await revokeAllTrustedDevices(String(userId));
    res.json({ ok: true } as OkResponseDto);
  } catch (e) {
    next(e);
  }
});
