// src/routes/auth/mfa.route.ts
import { Router } from 'express';
import { z } from 'zod';
import { pool } from '../../db/pool.js';
import argon2 from 'argon2';
import { signAccess, signRefresh } from '../../utils/jwt.js';
import { requireAuth } from '../../middleware/authz.js';
import { encryptToBlob, decryptFromBlob, sha256 } from '../../utils/crypto.js';
import {
  base32Encode,
  generateTotpSecret,
  otpauthURL,
  verifyTotp,
  generateBackupCodes,
} from '../../utils/totp.js';
import { env } from '../../config/env.js';
import { ulid } from 'ulid';
import { mfaVerifyLimiter } from '../../middleware/rateLimit.js';
import { RowDataPacket } from 'mysql2';
import type {
  AuthOutputDto,
  MfaSetupStartResponseDto,
  MfaSetupVerifyResponseDto,
  MfaBackupCodesResponseDto,
  OkResponseDto,
} from '@milemoto/types';
import {
  DisableMfa,
  backupHash,
  revokeAllTrustedDevices,
  setRefreshCookie,
  createTrustedDevice,
  ttlForRole,
} from './auth.helpers.js';
import { dbNow } from '../../db/time.js';

export const mfaAuth = Router();

// ===== MFA: start setup =====
mfaAuth.post('/mfa/setup/start', requireAuth, async (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    const userId = req.user.id;

    const [urows] = await pool.query<RowDataPacket[]>(
      'SELECT email, mfa_enabled FROM users WHERE id = ? LIMIT 1',
      [userId]
    );
    const u = urows[0];
    if (!u) return res.status(404).json({ error: 'User not found' });
    if (u.mfa_enabled) return res.status(400).json({ error: 'MFA already enabled' });

    const raw = generateTotpSecret(20);
    const secretEnc = encryptToBlob(raw);
    const challengeId = ulid();

    const exp = new Date((await dbNow()).getTime() + Number(env.MFA_CHALLENGE_TTL_SEC) * 1000);

    await pool.query(
      'INSERT INTO mfa_challenges (id, user_id, secret_enc, expires_at) VALUES (?, ?, ?, ?)',
      [challengeId, userId, secretEnc, exp]
    );

    const secretBase32 = base32Encode(raw);
    const uri = otpauthURL({
      issuer: 'MileMoto',
      account: u.email,
      secretBase32,
    });

    res.json({
      challengeId,
      secretBase32,
      otpauthUrl: uri,
      expiresAt: exp.toISOString(),
    } as MfaSetupStartResponseDto);
  } catch (e) {
    next(e);
  }
});

// ===== MFA: verify setup & enable =====
mfaAuth.post('/mfa/setup/verify', requireAuth, async (req, res, next) => {
  try {
    const { challengeId, code } = z
      .object({
        challengeId: z.string().min(10),
        code: z.string().regex(/^\d{6}$/),
      })
      .parse(req.body);
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    const userId = req.user.id;

    const [rows] = await pool.query<RowDataPacket[]>(
      'SELECT secret_enc, expires_at, consumed_at FROM mfa_challenges WHERE id = ? AND user_id = ? LIMIT 1',
      [challengeId, userId]
    );
    const ch = rows[0];
    if (!ch || ch.consumed_at)
      return res.status(400).json({ code: 'InvalidChallenge', message: 'Invalid challenge' });
    if (new Date(ch.expires_at) < new Date())
      return res.status(400).json({ code: 'ChallengeExpired', message: 'Challenge expired' });

    const secretRaw = decryptFromBlob(Buffer.from(ch.secret_enc));
    if (!verifyTotp(code, secretRaw))
      return res.status(400).json({ code: 'InvalidCode', message: 'Invalid 6-digit code' });

    await pool.query('UPDATE users SET mfa_secret_enc = ?, mfa_enabled = 1 WHERE id = ?', [
      ch.secret_enc,
      userId,
    ]);
    await pool.query('UPDATE mfa_challenges SET consumed_at = NOW() WHERE id = ?', [challengeId]);

    const { codes, hashes } = generateBackupCodes(10);
    if (hashes.length) {
      const values = hashes.map(() => '(?, ?)').join(', ');
      await pool.query(
        `INSERT INTO mfa_backup_codes (user_id, code_hash) VALUES ${values}`,
        hashes.flatMap((h) => [userId, h])
      );
    }

    await revokeAllTrustedDevices(String(userId));
    res.json({ ok: true, backupCodes: codes } as MfaSetupVerifyResponseDto);
  } catch (e) {
    next(e);
  }
});

// ===== MFA: disable (requires password + TOTP or backup code) =====
mfaAuth.post('/mfa/disable', requireAuth, async (req, res, next) => {
  try {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    const userId = String(req.user.id);
    const { password, code } = DisableMfa.parse(req.body);

    const [urows] = await pool.query<RowDataPacket[]>(
      `SELECT id, password_hash, mfa_enabled, mfa_secret_enc FROM users WHERE id = ? LIMIT 1`,
      [userId]
    );
    const u = urows[0];
    if (!u) return res.status(404).json({ error: 'User not found' });
    if (!u.mfa_enabled) return res.status(400).json({ error: 'MFA not enabled' });

    const passOk = await argon2.verify(u.password_hash, password);
    if (!passOk)
      return res.status(400).json({ code: 'InvalidPassword', message: 'Invalid password' });

    let ok = false;
    if (/^\d{6}$/.test(code)) {
      if (!u.mfa_secret_enc)
        return res.status(400).json({ code: 'MfaMisconfigured', message: 'MFA misconfigured' });
      const secretRaw = decryptFromBlob(Buffer.from(u.mfa_secret_enc));
      ok = verifyTotp(code, secretRaw);
    }
    if (!ok) {
      // Check for backup code
      const rawInput = code.toUpperCase().trim();
      const pretty =
        rawInput.length > 4 ? `${rawInput.slice(0, 4)}-${rawInput.slice(4)}` : rawInput;
      const candidates = [backupHash(rawInput), backupHash(pretty)];
      let bc: RowDataPacket | undefined;
      for (const h of candidates) {
        const [brows] = await pool.query<RowDataPacket[]>(
          `SELECT id FROM mfa_backup_codes WHERE user_id = ? AND code_hash = ? AND used_at IS NULL LIMIT 1`,
          [userId, h]
        );
        if (brows && brows[0]) {
          bc = brows[0];
          break;
        }
      }
      if (bc) {
        ok = true;
        await pool.query(`UPDATE mfa_backup_codes SET used_at = NOW() WHERE id = ?`, [bc.id]);
      }
    }
    if (!ok)
      return res.status(400).json({ code: 'InvalidCode', message: 'Invalid 2FA or backup code' });

    await pool.query(`UPDATE users SET mfa_enabled = 0, mfa_secret_enc = NULL WHERE id = ?`, [
      userId,
    ]);
    await pool.query(`DELETE FROM mfa_backup_codes WHERE user_id = ?`, [userId]);

    await revokeAllTrustedDevices(String(userId));
    res.json({ ok: true } as OkResponseDto);
  } catch (e) {
    next(e);
  }
});

// ===== MFA: regenerate backup codes =====
mfaAuth.post('/mfa/backup-codes/regen', requireAuth, async (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    const userId = req.user.id;

    await pool.query(
      'UPDATE mfa_backup_codes SET used_at = NOW() WHERE user_id = ? AND used_at IS NULL',
      [userId]
    );

    const { codes, hashes } = generateBackupCodes(10);
    if (hashes.length) {
      const values = hashes.map(() => '(?, ?)').join(', ');
      await pool.query(
        `INSERT INTO mfa_backup_codes (user_id, code_hash) VALUES ${values}`,
        hashes.flatMap((h) => [userId, h])
      );
    }
    res.json({ ok: true, backupCodes: codes } as MfaBackupCodesResponseDto);
  } catch (e) {
    next(e);
  }
});

// ===== MFA: verify login challenge =====
mfaAuth.post('/mfa/login/verify', mfaVerifyLimiter, async (req, res, next) => {
  try {
    const { challengeId, code, rememberDevice } = z
      .object({
        challengeId: z.string().min(10),
        code: z.string().min(4).max(64),
        rememberDevice: z.boolean().optional().default(false),
      })
      .parse(req.body);

    const [rows] = await pool.query<RowDataPacket[]>(
      `SELECT ml.user_id, ml.remember, ml.expires_at, ml.consumed_at,
              u.full_name, u.email, u.phone, u.role, u.mfa_secret_enc
         FROM mfa_login_challenges ml
         JOIN users u ON u.id = ml.user_id
        WHERE ml.id = ?
        LIMIT 1`,
      [challengeId]
    );
    const rec = rows[0];
    if (!rec || rec.consumed_at)
      return res.status(400).json({ code: 'InvalidChallenge', message: 'Invalid challenge' });
    if (new Date(rec.expires_at) < new Date())
      return res.status(400).json({ code: 'ChallengeExpired', message: 'Challenge expired' });

    const userId = String(rec.user_id);
    let ok = false;

    if (/^\d{6}$/.test(code)) {
      if (!rec.mfa_secret_enc)
        return res.status(400).json({ code: 'MfaMisconfigured', message: 'MFA misconfigured' });
      const secretRaw = decryptFromBlob(Buffer.from(rec.mfa_secret_enc));
      ok = verifyTotp(code, secretRaw);
    }

    if (!ok) {
      const h = backupHash(code.toUpperCase().trim());
      const [brows] = await pool.query<RowDataPacket[]>(
        `SELECT id FROM mfa_backup_codes
          WHERE user_id = ? AND code_hash = ? AND used_at IS NULL
          LIMIT 1`,
        [userId, h]
      );
      const bc = brows[0];
      if (bc) {
        ok = true;
        await pool.query(`UPDATE mfa_backup_codes SET used_at = NOW() WHERE id = ?`, [bc.id]);
      }
    }

    if (!ok)
      return res.status(400).json({ code: 'InvalidCode', message: 'Invalid 2FA or backup code' });

    await pool.query(`UPDATE mfa_login_challenges SET consumed_at = NOW() WHERE id = ?`, [
      challengeId,
    ]);

    const role = rec.role as 'user' | 'admin';
    const remember = Boolean(rec.remember);
    const ttlSec = ttlForRole(role, remember);
    const sid = ulid();
    const refresh = signRefresh({ sub: userId, sid }, ttlSec);
    const refreshHash = sha256(refresh);
    const now = await dbNow();
    const exp = new Date(now.getTime() + ttlSec * 1000);

    await pool.query(
      `INSERT INTO sessions (id, user_id, refresh_hash, user_agent, ip, remember, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        sid,
        userId,
        refreshHash,
        req.get('user-agent') ?? null,
        req.ip ?? null,
        remember ? 1 : 0,
        exp,
      ]
    );

    setRefreshCookie(res, refresh, { remember, maxAgeSec: ttlSec });
    if (rememberDevice) {
      await createTrustedDevice(req, res, userId);
    }
    const access = signAccess({ sub: userId, role });
    res.json({
      accessToken: access,
      user: {
        id: String(userId),
        fullName: rec.full_name,
        email: rec.email,
        phone: rec.phone,
        role,
        mfaEnabled: true,
      },
    } as AuthOutputDto);
  } catch (e) {
    next(e);
  }
});
