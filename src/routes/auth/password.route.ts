// src/routes/auth/password.route.ts
import { Router } from 'express';
import argon2 from 'argon2';
import { pool } from '../../db/pool.js';
import { sha256, randToken } from '../../utils/crypto.js';
import { logger } from '../../utils/logger.js';
import { env } from '../../config/env.js';
import { RowDataPacket } from 'mysql2';
import { sendPasswordResetEmail } from '../../services/emailService.js';
import { requireAuth } from '../../middleware/authz.js';
import type { OkResponseDto } from '@milemoto/types';
import { z } from 'zod';
import {
  ChangePassword,
  VerifyEmail,
  ResendVerification,
  revokeAllTrustedDevices,
  sendNewVerificationEmail,
} from './auth.helpers.js';
import { dbNow } from '../../db/time.js';

export const passwordAuth = Router();

// ===== Change Password (Logged-In) =====
passwordAuth.post('/change-password', requireAuth, async (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    const userId = req.user.id;

    const { oldPassword, newPassword } = ChangePassword.parse(req.body);

    const [rows] = await pool.query<RowDataPacket[]>(
      'SELECT password_hash FROM users WHERE id = ?',
      [userId]
    );
    const u = rows[0];

    if (!u || !u.password_hash) {
      return res.status(404).json({ error: 'User not found' });
    }

    const ok = await argon2.verify(u.password_hash, oldPassword);
    if (!ok) {
      return res.status(401).json({ error: 'Invalid current password' });
    }

    const newHash = await argon2.hash(newPassword, { type: argon2.argon2id });
    await pool.query('UPDATE users SET password_hash = ? WHERE id = ?', [newHash, userId]);

    await pool.query('UPDATE sessions SET revoked_at = NOW() WHERE user_id = ?', [userId]);
    await revokeAllTrustedDevices(String(userId));
    res.json({ ok: true } as OkResponseDto);
  } catch (e) {
    next(e);
  }
});

// ===== Verify Email =====
passwordAuth.post('/verify-email', async (req, res, next) => {
  try {
    const { token } = VerifyEmail.parse(req.body);
    const hash = sha256(token);

    const [rows] = await pool.query<RowDataPacket[]>(
      `SELECT id, user_id FROM email_verifications
       WHERE token_hash = ? AND used_at IS NULL AND expires_at > NOW()
       LIMIT 1`,
      [hash]
    );
    const verification = rows[0];

    if (!verification) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    await pool.query('UPDATE email_verifications SET used_at = NOW() WHERE id = ?', [
      verification.id,
    ]);
    await pool.query('UPDATE users SET email_verified_at = NOW() WHERE id = ?', [
      verification.user_id,
    ]);

    await revokeAllTrustedDevices(String(verification.user_id));
    res.json({ ok: true } as OkResponseDto);
  } catch (e) {
    next(e);
  }
});

// ===== Resend Verification Email =====
passwordAuth.post('/verify-email/resend', async (req, res, next) => {
  try {
    const { email } = ResendVerification.parse(req.body);

    const [rows] = await pool.query<RowDataPacket[]>(
      'SELECT id, email_verified_at FROM users WHERE email = ? LIMIT 1',
      [email.toLowerCase()]
    );
    const u = rows[0];

    if (u && !u.email_verified_at) {
      void sendNewVerificationEmail(String(u.id), email.toLowerCase());
    }

    // Always return OK to prevent email enumeration
    if (u) {
      await revokeAllTrustedDevices(String(u.id));
    }
    res.json({ ok: true } as OkResponseDto);
  } catch (e) {
    if (e instanceof z.ZodError) {
      return res.status(400).json({ error: 'Invalid request' });
    }
    next(e);
  }
});

/** POST /api/auth/forgot */
passwordAuth.post('/forgot', async (req, res, next) => {
  try {
    const email = z.string().email().parse(req.body?.email);
    const [rows] = await pool.query<RowDataPacket[]>(
      `SELECT id FROM users WHERE email = ? LIMIT 1`,
      [email.toLowerCase()]
    );
    const u = rows[0];
    if (u) {
      const token = randToken(32);
      const hash = sha256(token);
      const now = await dbNow();
      const exp = new Date(now.getTime() + 60 * 60 * 1000); // 1h
      await pool.query(
        `INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (?, ?, ?)`,
        [String(u.id), hash, exp]
      );
      const resetUrl = `${env.FRONTEND_BASE_URL}/reset-password?token=${token}`;

      try {
        await sendPasswordResetEmail(email.toLowerCase(), resetUrl);
        if (env.NODE_ENV === 'development') {
          logger.info({ resetUrl }, 'Password reset link sent');
        }
      } catch (emailError) {
        logger.error({ err: emailError, email }, 'Failed to send password reset email');
      }
    }

    // Always send a generic success response
    if (u) {
      await revokeAllTrustedDevices(String(u.id));
    }
    res.json({ ok: true } as OkResponseDto);
  } catch (e) {
    if (e instanceof z.ZodError) {
      return res.status(400).json({ error: 'Invalid request' });
    }
    next(e);
  }
});

/** POST /api/auth/reset */
passwordAuth.post('/reset', async (req, res, next) => {
  try {
    const body = z
      .object({
        token: z.string().min(10),
        password: z.string().min(8).max(128),
      })
      .parse(req.body);
    const hash = sha256(body.token);
    const [rows] = await pool.query<RowDataPacket[]>(
      `SELECT pr.id, pr.user_id FROM password_resets pr
       WHERE pr.token_hash = ? AND pr.used_at IS NULL AND pr.expires_at > NOW()
       LIMIT 1`,
      [hash]
    );
    const r = rows[0];
    if (!r) return res.status(400).json({ error: 'Invalid or expired token' });

    const pwHash = await argon2.hash(body.password, { type: argon2.argon2id });
    await pool.query(`UPDATE users SET password_hash = ? WHERE id = ?`, [
      pwHash,
      String(r.user_id),
    ]);
    await pool.query(`UPDATE password_resets SET used_at = NOW() WHERE id = ?`, [r.id]);

    await pool.query(`UPDATE sessions SET revoked_at = NOW() WHERE user_id = ?`, [
      String(r.user_id),
    ]);
    await revokeAllTrustedDevices(String(r.user_id));
    res.json({ ok: true } as OkResponseDto);
  } catch (e) {
    if (e instanceof z.ZodError) {
      return res.status(400).json({ error: 'Invalid request' });
    }
    next(e);
  }
});
