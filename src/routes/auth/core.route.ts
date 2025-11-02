// src/routes/auth/core.route.ts
import { Router } from 'express';
import argon2 from 'argon2';
import { pool } from '../../db/pool.js';
import { signAccess, signRefresh, verifyRefresh } from '../../utils/jwt.js';
import { requireAuth } from '../../middleware/authz.js';
import { sha256 } from '../../utils/crypto.js';
import { logger } from '../../utils/logger.js';
import { env } from '../../config/env.js';
import { ulid } from 'ulid';
import { loginByIpLimiter, loginByEmailLimiter } from '../../middleware/rateLimit.js';
import { ResultSetHeader, RowDataPacket } from 'mysql2';
import type {
  AuthOutputDto,
  MfaChallengeDto,
  RefreshResponseDto,
  RegisterResponseDto,
} from '@milemoto/types';
import {
  Login,
  Register,
  validateTrustedCookie,
  setRefreshCookie,
  ttlForRole,
  sendNewVerificationEmail,
  revokeAllTrustedDevices,
} from './auth.helpers.js';

export const coreAuth = Router();

/** POST /api/auth/register */
coreAuth.post('/register', async (req, res, next) => {
  try {
    const { fullName, email, phone, password } = Register.parse(req.body);
    const hash = await argon2.hash(password, { type: argon2.argon2id });

    const [result] = await pool.query<ResultSetHeader>(
      `INSERT INTO users (full_name, email, phone, password_hash, role, status)
       VALUES (?, ?, ?, ?, 'user', 'active')`,
      [fullName, email.toLowerCase(), phone ?? null, hash]
    );

    const userId = String(result.insertId);

    // --- Send Verification Email ---
    try {
      await sendNewVerificationEmail(userId, email);
    } catch (emailError: unknown) {
      logger.error(
        { err: emailError, emailHash: sha256(email.toLowerCase()) },
        'Failed to send verification email'
      );
    }
    res.status(201).json({ ok: true, userId: userId } as RegisterResponseDto);
  } catch (e: unknown) {
    if (e && typeof e === 'object' && 'code' in e) {
      const error = e as { code?: string; message?: string }; // Cast after checking

      if (error.code === 'ER_DUP_ENTRY') {
        if (error.message && error.message.includes('uniq_users_phone')) {
          return res.status(409).json({
            message: 'Phone number already registered',
            code: 'ER_DUP_PHONE',
          });
        }

        return res.status(409).json({
          message: 'Email address already registered',
          code: 'ER_DUP_EMAIL',
        });
      }
    }
    next(e);
  }
});

/** POST /api/auth/login */
coreAuth.post('/login', loginByIpLimiter, loginByEmailLimiter, async (req, res, next) => {
  try {
    const { email, password, remember } = Login.parse(req.body);

    const [rows] = await pool.query<RowDataPacket[]>(
      `SELECT id, full_name, email, phone, password_hash, role, status, mfa_enabled, email_verified_at
         FROM users WHERE email = ? LIMIT 1`,
      [email.toLowerCase()]
    );
    const u = rows[0];
    if (!u) return res.status(401).json({ error: 'Invalid credentials' });
    if (u.status !== 'active') return res.status(403).json({ error: 'Account disabled' });

    const ok = await argon2.verify(u.password_hash, password);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    if (!u.email_verified_at) {
      return res.status(403).json({
        error: 'Email Not Verified',
        message: 'Please verify your email address before logging in.',
      });
    }

    if (u.mfa_enabled) {
      try {
        const isTrusted = await validateTrustedCookie(
          req,
          String(u.id),
          u.role as 'user' | 'admin'
        );
        if (isTrusted) {
          // ... (full logic for trusted device login)
          const role = u.role as 'user' | 'admin';
          const ttlSec = ttlForRole(role, Boolean(remember));
          const sid = ulid();
          const refresh = signRefresh({ sub: String(u.id), sid }, ttlSec);
          const refreshHash = sha256(refresh);
          const [row2] = await pool.query<RowDataPacket[]>('SELECT NOW() AS now');
          const now2 = new Date(row2[0].now);
          const exp2 = new Date(now2.getTime() + ttlSec * 1000);
          await pool.query(
            `INSERT INTO sessions (id, user_id, refresh_hash, user_agent, ip, remember, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
              sid,
              String(u.id),
              refreshHash,
              req.get('user-agent') ?? null,
              req.ip ?? null,
              remember ? 1 : 0,
              exp2,
            ]
          );
          setRefreshCookie(res, refresh, { remember: Boolean(remember), maxAgeSec: ttlSec });
          const access = signAccess({ sub: String(u.id), role });
          return res.json({
            accessToken: access,
            user: {
              id: String(u.id),
              fullName: u.full_name,
              email: u.email,
              phone: u.phone,
              role,
              mfaEnabled: Boolean(u.mfa_enabled),
            },
          } as AuthOutputDto);
        }
      } catch (err) {
        logger.error(
          { err, userId: String(u.id) },
          'Trusted-device bypass failed; falling back to MFA'
        );
      }

      const pendingId = ulid();
      const [row] = await pool.query<RowDataPacket[]>('SELECT NOW() AS now');
      const now = new Date(row[0].now);
      const exp = new Date(now.getTime() + Number(env.MFA_LOGIN_TTL_SEC) * 1000);

      await pool.query(
        `INSERT INTO mfa_login_challenges (id, user_id, remember, user_agent, ip, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [
          pendingId,
          String(u.id),
          remember ? 1 : 0,
          req.get('user-agent') ?? null,
          req.ip ?? null,
          exp,
        ]
      );

      return res.json({
        mfaRequired: true,
        challengeId: pendingId,
        method: 'totp_or_backup',
        expiresAt: exp.toISOString(),
      } as MfaChallengeDto);
    }

    // No MFA: create session and return tokens
    const role = u.role as 'user' | 'admin';
    const ttlSec = ttlForRole(role, Boolean(remember));
    const sid = ulid();
    const refresh = signRefresh({ sub: String(u.id), sid }, ttlSec);
    const refreshHash = sha256(refresh);

    const [row2] = await pool.query<RowDataPacket[]>('SELECT NOW() AS now');
    const now2 = new Date(row2[0].now);
    const exp2 = new Date(now2.getTime() + ttlSec * 1000);

    await pool.query(
      `INSERT INTO sessions (id, user_id, refresh_hash, user_agent, ip, remember, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        sid,
        String(u.id),
        refreshHash,
        req.get('user-agent') ?? null,
        req.ip ?? null,
        remember ? 1 : 0,
        exp2,
      ]
    );

    setRefreshCookie(res, refresh, { remember: Boolean(remember), maxAgeSec: ttlSec });
    const access = signAccess({ sub: String(u.id), role });
    res.json({
      accessToken: access,
      user: {
        id: String(u.id),
        fullName: u.full_name,
        email: u.email,
        phone: u.phone,
        role,
        mfaEnabled: Boolean(u.mfa_enabled),
      },
    } as AuthOutputDto);
  } catch (e) {
    next(e);
  }
});

/** POST /api/auth/refresh */
coreAuth.post('/refresh', async (req, res, next) => {
  try {
    const token = req.cookies?.[env.REFRESH_COOKIE_NAME];
    if (!token) return res.status(401).json({ error: 'No refresh' });

    const { sid, sub: userId } = verifyRefresh(token);

    const [rows] = await pool.query<RowDataPacket[]>(
      `SELECT refresh_hash, revoked_at, expires_at, remember
         FROM sessions WHERE id = ? AND user_id = ? LIMIT 1`,
      [sid, userId]
    );
    const s = rows[0];
    if (!s || s.revoked_at || new Date(s.expires_at) < new Date()) {
      return res.status(401).json({ error: 'Invalid session' });
    }
    if (sha256(token) !== s.refresh_hash) {
      await pool.query(`UPDATE sessions SET revoked_at = NOW() WHERE id = ?`, [sid]);
      return res.status(401).json({ error: 'Token reuse detected' });
    }

    const [urows] = await pool.query<RowDataPacket[]>(
      `SELECT role FROM users WHERE id = ? LIMIT 1`,
      [userId]
    );
    const role = urows[0].role as 'user' | 'admin';
    const remember = Boolean(s.remember);
    const ttlSec = ttlForRole(role, remember);

    const newSid = ulid();
    const newRefresh = signRefresh({ sub: userId, sid: newSid }, ttlSec);
    const newHash = sha256(newRefresh);

    await pool.query(`UPDATE sessions SET revoked_at = NOW(), replaced_by = ? WHERE id = ?`, [
      newSid,
      sid,
    ]);

    const [row] = await pool.query<RowDataPacket[]>('SELECT NOW() AS now');
    const now = new Date(row[0].now);
    const exp = new Date(now.getTime() + ttlSec * 1000);

    await pool.query(
      `INSERT INTO sessions (id, user_id, refresh_hash, user_agent, ip, remember, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        newSid,
        userId,
        newHash,
        req.get('user-agent') ?? null,
        req.ip ?? null,
        remember ? 1 : 0,
        exp,
      ]
    );

    setRefreshCookie(res, newRefresh, { remember, maxAgeSec: ttlSec });
    const access = signAccess({ sub: userId, role });

    res.json({ accessToken: access } as RefreshResponseDto);
  } catch (error) {
    next(error);
  }
});

/** POST /api/auth/logout */
coreAuth.post('/logout', async (req, res) => {
  try {
    const token = req.cookies?.[env.REFRESH_COOKIE_NAME];
    if (token) {
      try {
        const { sid } = verifyRefresh(token);
        await pool.query(`UPDATE sessions SET revoked_at = NOW() WHERE id = ?`, [sid]);
      } catch {
        /* ignore */
      }
    }
    res.clearCookie(env.REFRESH_COOKIE_NAME, {
      path: '/api',
      domain: env.COOKIE_DOMAIN || undefined,
      sameSite: 'lax',
      secure: env.NODE_ENV === 'production',
    });

    res.status(204).end();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
});

/** POST /api/auth/logout-all */
coreAuth.post('/logout-all', requireAuth, async (req, res, next) => {
  try {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    const userId = String(req.user.id);

    await pool.query(
      `UPDATE sessions SET revoked_at = NOW() WHERE user_id = ? AND revoked_at IS NULL`,
      [userId]
    );
    await revokeAllTrustedDevices(userId);

    res.clearCookie(env.REFRESH_COOKIE_NAME, {
      path: '/api',
      domain: env.COOKIE_DOMAIN || undefined,
      sameSite: 'lax',
      secure: env.NODE_ENV === 'production',
    });
    res.clearCookie('mm_trusted', {
      path: '/',
      domain: env.COOKIE_DOMAIN || undefined,
      sameSite: 'lax',
      secure: env.NODE_ENV === 'production',
    });

    logger.info({ code: 'UserLogoutAll', userId }, 'User requested logout on all devices');
    return res.status(204).end();
  } catch (e) {
    next(e);
    return res.status(500).json({ error: 'Failed to logout all' });
  }
});
