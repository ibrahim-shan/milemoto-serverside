import { Router, type Response } from 'express';
import { z } from 'zod';
import argon2 from 'argon2';
import { pool } from '../db/pool.js';
import crypto from 'crypto';
import { signAccess, signRefresh, verifyAccess, verifyRefresh } from '../utils/jwt.js';
import { requireAuth } from '../middleware/authz.js';
import { encryptToBlob, decryptFromBlob, sha256, randToken } from '../utils/crypto.js';
import { logger } from '../utils/logger.js';
import {
  base32Encode,
  generateTotpSecret,
  otpauthURL,
  verifyTotp,
  generateBackupCodes,
} from '../utils/totp.js';
import { env } from '../config/env.js';
import { ulid } from 'ulid';
import {
  loginByIpLimiter,
  loginByEmailLimiter,
  mfaVerifyLimiter,
} from '../middleware/rateLimit.js';
import { ResultSetHeader, RowDataPacket } from 'mysql2';
import { sendPasswordResetEmail, sendVerificationEmail } from '../services/emailService.js';

import type {
  AuthOutputDto,
  MfaChallengeDto,
  MfaSetupStartResponseDto,
  MfaSetupVerifyResponseDto,
  MfaBackupCodesResponseDto,
  OkResponseDto,
  RefreshResponseDto,
  RegisterResponseDto,
  UserDto,
} from '';

interface UserAuthData {
  id: string | number;
  full_name: string;
  email: string;
  phone: string | null;
  role: 'user' | 'admin';
  status: 'active' | 'disabled';
  mfa_enabled: 0 | 1;
  email_verified_at?: Date | string | null;
}

export const auth = Router();

// CSRF defense-in-depth: check Origin/Referer for POSTs to /api/auth
const allowedOrigins = new Set(env.CORS_ORIGINS.split(',').map((s) => s.trim()));
auth.use((req, res, next) => {
  if (req.method.toUpperCase() !== 'POST') return next();
  const origin = req.get('origin') || '';
  const referer = req.get('referer') || '';
  const allowByOrigin = origin && allowedOrigins.has(origin);
  let allowByReferer = false;
  if (referer) {
    try {
      const u = new URL(referer);
      allowByReferer = allowedOrigins.has(u.origin);
    } catch {}
  }
  // Allow if header absent (non-browser clients), or if origin/referrer is whitelisted
  if ((!origin && !referer) || allowByOrigin || allowByReferer) return next();
  return res.status(403).json({ error: 'CSRF blocked' });
});

const Register = z.object({
  fullName: z.string().min(2).max(191),
  email: z.string().email().max(191),
  phone: z.string().min(7).max(32).optional(),
  password: z.string().min(8).max(128),
  remember: z.coerce.boolean().optional().default(false),
});

const ChangePassword = z.object({
  oldPassword: z.string().min(8),
  newPassword: z.string().min(8).max(128),
});

const VerifyEmail = z.object({
  token: z.string().min(32),
});

const ResendVerification = z.object({
  email: z.string().email(),
});

const Login = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  remember: z.coerce.boolean().optional().default(false), // new (controls cookie persistence)
});

function backupHash(code: string) {
  return crypto.createHmac('sha256', env.BACKUP_CODE_HMAC_SECRET).update(code).digest('hex');
}

function setRefreshCookie(
  res: Response,
  token: string,
  opts: { remember: boolean; maxAgeSec: number }
) {
  const base = {
    httpOnly: true,
    secure: env.NODE_ENV === 'production',
    sameSite: 'lax' as const,
    domain: env.COOKIE_DOMAIN || undefined,
    path: '/api/auth',
  };
  if (opts.remember) {
    // persistent cookie
    res.cookie(env.REFRESH_COOKIE_NAME, token, {
      ...base,
      maxAge: opts.maxAgeSec * 1000,
    });
  } else {
    // session cookie (no maxAge)
    res.cookie(env.REFRESH_COOKIE_NAME, token, base);
  }
}

function signState(payload: { next: string; remember: boolean }) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', env.OAUTH_STATE_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function verifyState(state: string): { next: string; remember: boolean } | null {
  const [body, sig] = state.split('.');
  if (!body || !sig) return null;
  const exp = crypto.createHmac('sha256', env.OAUTH_STATE_SECRET).update(body).digest('base64url');
  const ok =
    exp.length === sig.length && crypto.timingSafeEqual(Buffer.from(exp), Buffer.from(sig));
  if (!ok) return null;
  try {
    return JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}
function safeNext(n: unknown): string {
  let s: string | undefined = undefined;

  if (typeof n === 'string') {
    s = n;
  } else if (Array.isArray(n) && n.length > 0 && typeof n[0] === 'string') {
    s = n[0];
  }
  if (s && s.startsWith('/') && !s.startsWith('//')) {
    return s;
  }
  return '/account';
}

function ttlForRole(role: 'user' | 'admin', remember: boolean) {
  if (role === 'admin') {
    return remember
      ? Number(env.ADMIN_REFRESH_TOKEN_TTL_SEC)
      : Number(env.ADMIN_SESSION_REFRESH_TTL_SEC);
  }
  return remember
    ? Number(env.USER_REFRESH_TOKEN_TTL_SEC)
    : Number(env.USER_SESSION_REFRESH_TTL_SEC);
}

async function sendNewVerificationEmail(userId: string, email: string) {
  try {
    const token = randToken(32);
    const hash = sha256(token);
    const [row] = await pool.query<RowDataPacket[]>('SELECT NOW() AS now');
    // Set expiry for 24 hours
    const exp = new Date(new Date(row[0].now).getTime() + 24 * 60 * 60 * 1000);

    await pool.query(
      `INSERT INTO email_verifications (user_id, token_hash, expires_at) VALUES (?, ?, ?)`,
      [userId, hash, exp]
    );

    const verifyUrl = `${env.FRONTEND_BASE_URL}/verify-email?token=${token}`;

    await sendVerificationEmail(email.toLowerCase(), verifyUrl);
  } catch (emailError: unknown) {
    logger.error(
      { err: emailError, emailHash: sha256(email.toLowerCase()) },
      'Failed to send verification email'
    );
  }
}

// ===== MFA: start setup =====
auth.post('/mfa/setup/start', requireAuth, async (req, res, next) => {
  try {
    if (!req.user) {
      // This should be unreachable if requireAuth is working, but it satisfies TypeScript
      return res.status(401).json({ error: 'Authentication required' });
    }
    const userId = req.user.id;

    // already enabled?
    const [urows] = await pool.query<RowDataPacket[]>(
      'SELECT email, mfa_enabled FROM users WHERE id = ? LIMIT 1',
      [userId]
    );
    const u = urows[0];
    if (!u) return res.status(404).json({ error: 'User not found' });
    if (u.mfa_enabled) return res.status(400).json({ error: 'MFA already enabled' });

    // generate secret and challenge
    const raw = generateTotpSecret(20);
    const secretEnc = encryptToBlob(raw);
    const challengeId = ulid();

    const [row] = await pool.query<RowDataPacket[]>('SELECT NOW() AS now');
    const exp = new Date(new Date(row[0].now).getTime() + Number(env.MFA_CHALLENGE_TTL_SEC) * 1000);

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

    // Frontend will render QR from `uri` (e.g., with qrcode)
    res.json({
      challengeId,
      secretBase32,
      otpauthUrl: uri,
      expiresAt: exp.toISOString(),
    } as MfaSetupStartResponseDto);
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
});

// ===== MFA: verify setup & enable =====
auth.post('/mfa/setup/verify', requireAuth, async (req, res, next) => {
  try {
    const { challengeId, code } = z
      .object({
        challengeId: z.string().min(10),
        code: z.string().regex(/^\d{6}$/),
      })
      .parse(req.body);
    if (!req.user) {
      // This should be unreachable if requireAuth is working, but it satisfies TypeScript
      return res.status(401).json({ error: 'Authentication required' });
    }
    const userId = req.user.id;

    const [rows] = await pool.query<RowDataPacket[]>(
      'SELECT secret_enc, expires_at, consumed_at FROM mfa_challenges WHERE id = ? AND user_id = ? LIMIT 1',
      [challengeId, userId]
    );
    const ch = rows[0];
    if (!ch || ch.consumed_at) return res.status(400).json({ error: 'Invalid challenge' });
    if (new Date(ch.expires_at) < new Date())
      return res.status(400).json({ error: 'Challenge expired' });

    const secretRaw = decryptFromBlob(Buffer.from(ch.secret_enc));
    if (!verifyTotp(code, secretRaw)) return res.status(400).json({ error: 'Invalid code' });

    // persist on user
    await pool.query('UPDATE users SET mfa_secret_enc = ?, mfa_enabled = 1 WHERE id = ?', [
      ch.secret_enc,
      userId,
    ]);
    await pool.query('UPDATE mfa_challenges SET consumed_at = NOW() WHERE id = ?', [challengeId]);

    // create backup codes
    const { codes, hashes } = generateBackupCodes(10);
    if (hashes.length) {
      const values = hashes.map(() => '(?, ?)').join(', ');
      await pool.query(
        `INSERT INTO mfa_backup_codes (user_id, code_hash) VALUES ${values}`,
        hashes.flatMap((h) => [userId, h])
      );
    }

    // Return plaintext codes ONCE. Client must show/save them.
    res.json({ ok: true, backupCodes: codes } as MfaSetupVerifyResponseDto);
  } catch (e) {
    next(e);
  }
});

// ===== MFA: regenerate backup codes =====
auth.post('/mfa/backup-codes/regen', requireAuth, async (req, res, next) => {
  try {
    if (!req.user) {
      // This should be unreachable if requireAuth is working, but it satisfies TypeScript
      return res.status(401).json({ error: 'Authentication required' });
    }
    const userId = req.user.id;

    // Invalidate all prior codes by marking used_at now (optional policy)
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

// ===== Change Password (Logged-In) =====
auth.post('/change-password', requireAuth, async (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    const userId = req.user.id;

    const { oldPassword, newPassword } = ChangePassword.parse(req.body);

    // 1. Get the user's current hash
    const [rows] = await pool.query<RowDataPacket[]>(
      'SELECT password_hash FROM users WHERE id = ?',
      [userId]
    );
    const u = rows[0];

    if (!u || !u.password_hash) {
      return res.status(404).json({ error: 'User not found' });
    }

    // 2. Verify the old password
    const ok = await argon2.verify(u.password_hash, oldPassword);
    if (!ok) {
      return res.status(401).json({ error: 'Invalid current password' });
    }

    // 3. Hash and set the new password
    const newHash = await argon2.hash(newPassword, { type: argon2.argon2id });
    await pool.query('UPDATE users SET password_hash = ? WHERE id = ?', [newHash, userId]);

    // 4. (Recommended Security) Revoke all other sessions for this user
    await pool.query('UPDATE sessions SET revoked_at = NOW() WHERE user_id = ?', [userId]);

    res.json({ ok: true } as OkResponseDto);
  } catch (e) {
    next(e);
  }
});

// ===== Verify Email =====
auth.post('/verify-email', async (req, res, next) => {
  try {
    const { token } = VerifyEmail.parse(req.body);
    const hash = sha256(token);

    // 1. Find the token
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

    // 2. Mark token as used
    await pool.query('UPDATE email_verifications SET used_at = NOW() WHERE id = ?', [
      verification.id,
    ]);

    // 3. Mark user as verified
    await pool.query('UPDATE users SET email_verified_at = NOW() WHERE id = ?', [
      verification.user_id,
    ]);

    res.json({ ok: true } as OkResponseDto);
  } catch (e) {
    next(e);
  }
});

/** POST /api/auth/register */
auth.post('/register', async (req, res, next) => {
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
      const token = randToken(32);
      const hash = sha256(token);
      const [row] = await pool.query<RowDataPacket[]>('SELECT NOW() AS now');
      // Set expiry for 24 hours
      const exp = new Date(new Date(row[0].now).getTime() + 24 * 60 * 60 * 1000);

      await pool.query(
        `INSERT INTO email_verifications (user_id, token_hash, expires_at) VALUES (?, ?, ?)`,
        [userId, hash, exp]
      );

      const verifyUrl = `${env.FRONTEND_BASE_URL}/verify-email?token=${token}`;

      await sendVerificationEmail(email.toLowerCase(), verifyUrl);
    } catch (emailError: unknown) {
      logger.error(
        { err: emailError, emailHash: sha256(email.toLowerCase()) },
        'Failed to send verification email'
      );
    }
    // Respond with a simple success message
    res.status(201).json({ ok: true, userId: userId } as RegisterResponseDto);
  } catch (e: unknown) {
    if (e && typeof e === 'object' && 'code' in e && e.code === 'ER_DUP_ENTRY')
      return res.status(409).json({ error: 'Email already registered' });
    return next(e);
  }
});

// src/routes/auth.ts  (add routes)
auth.get('/google/start', (req, res) => {
  const next = safeNext(req.query.next);
  const remember = String(req.query.remember) === '1' || String(req.query.remember) === 'true';
  const state = signState({ next, remember });

  const redirectUri = `${req.protocol}://${req.get('host')}/api/auth/google/callback`;

  const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  url.searchParams.set('client_id', env.GOOGLE_CLIENT_ID);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'openid email profile');
  url.searchParams.set('state', state);
  url.searchParams.set('prompt', 'select_account');

  return res.redirect(url.toString());
});

auth.get('/google/callback', async (req, res, next) => {
  try {
    const code = String(req.query.code || '');
    const stateStr = String(req.query.state || '');
    const state = verifyState(stateStr);
    if (!code || !state) return res.status(400).send('Invalid OAuth state');

    const redirectUri = `${req.protocol}://${req.get('host')}/api/auth/google/callback`;

    // Exchange code
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: env.GOOGLE_CLIENT_ID,
        client_secret: env.GOOGLE_CLIENT_SECRET,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code',
      }),
    });
    if (!tokenRes.ok) return res.status(400).send('Token exchange failed');
    const tok = (await tokenRes.json()) as {
      id_token?: string;
      access_token?: string;
    };
    if (!tok.id_token) return res.status(400).send('No id_token');

    // Decode id_token (no remote signature verification here)
    const [, payloadB64] = tok.id_token.split('.');
    const info = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8')) as {
      iss: string;
      aud: string;
      exp: number;
      sub: string;
      email?: string;
      email_verified?: boolean;
      name?: string;
      given_name?: string;
      family_name?: string;
      picture?: string;
    };

    // ✅ minimal claim checks
    const nowSec = Math.floor(Date.now() / 1000);
    const validIssuer =
      info.iss === 'https://accounts.google.com' || info.iss === 'accounts.google.com';

    if (!validIssuer) return res.status(400).send('Bad iss');
    if (info.aud !== env.GOOGLE_CLIENT_ID) return res.status(400).send('Bad aud');
    if (typeof info.exp !== 'number' || info.exp <= nowSec)
      return res.status(400).send('Token expired');

    // Enforce verified emails (recommended)
    if (info.email_verified !== true) return res.status(400).send('Email not verified');

    const gsub = info.sub;
    const emailRaw = info.email || '';
    if (!emailRaw) return res.status(400).send('Google account missing email'); // <-- ADD HERE
    const email = emailRaw.toLowerCase();

    const name =
      info.name ||
      `${info.given_name || ''} ${info.family_name || ''}`.trim() ||
      email.split('@')[0];

    // Link or create user
    const [bySubRows] = await pool.query<RowDataPacket[]>(
      `SELECT id, full_name, email, phone, role, status, mfa_enabled, email_verified_at
   FROM users WHERE google_sub = ? LIMIT 1`,
      [gsub]
    );
    let u = bySubRows[0] as UserAuthData | undefined;

    if (!u && email) {
      // by email:
      const [byEmailRows] = await pool.query<RowDataPacket[]>(
        `SELECT id, full_name, email, phone, role, status, google_sub, mfa_enabled, email_verified_at
     FROM users WHERE email = ? LIMIT 1`,
        [email]
      );
      const existing = byEmailRows[0] as UserAuthData | undefined;
      if (existing) {
        await pool.query(
          `UPDATE users
         SET google_sub = ?, email_verified_at = IFNULL(email_verified_at, ?)
       WHERE id = ?`,
          [gsub, info.email_verified ? new Date() : null, existing.id]
        );
        u = {
          ...existing,
          google_sub: gsub,
          email_verified_at:
            existing.email_verified_at ?? (info.email_verified ? new Date() : null),
        } as UserAuthData;
      }
    }

    if (!u) {
      const randomPw = crypto.randomBytes(16).toString('hex');
      const hash = await argon2.hash(randomPw, { type: argon2.argon2id });
      const [ins] = await pool.query<ResultSetHeader>(
        `INSERT INTO users (full_name, email, password_hash, role, status, email_verified_at, google_sub)
         VALUES (?, ?, ?, 'user', 'active', ?, ?)`,
        [name, email, hash, info.email_verified ? new Date() : null, gsub]
      );
      const userId = String(ins.insertId);

      const newUser: UserAuthData = {
        id: userId,
        full_name: name,
        email,
        phone: null,
        role: 'user',
        status: 'active',
        mfa_enabled: 0,
      };
      u = newUser;
    }

    if (!u.email_verified_at) {
      // Redirect to a frontend page that says "Please check your email to verify"
      // You can create this page or just redirect to signin with an error.
      return res.redirect(`${env.FRONTEND_BASE_URL}/signin?error=EmailNotVerified`);
    }

    if (u.mfa_enabled) {
      const pendingId = ulid();

      const [rowNow] = await pool.query<RowDataPacket[]>('SELECT NOW() AS now');
      const now = new Date(rowNow[0].now);
      const exp = new Date(now.getTime() + Number(env.MFA_LOGIN_TTL_SEC) * 1000);

      await pool.query(
        `INSERT INTO mfa_login_challenges
       (id, user_id, remember, user_agent, ip, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
        [
          pendingId,
          String(u.id),
          state.remember ? 1 : 0,
          req.get('user-agent') ?? null,
          req.ip ?? null,
          exp,
        ]
      );

      // Tell frontend to show the MFA step
      const frag = new URLSearchParams({
        mfaRequired: '1',
        challengeId: pendingId, // <-- Now this is valid
        expiresAt: exp.toISOString(),
        store: state.remember ? 'local' : 'session', // <-- The new line
        next: state.next || '/account', // <-- The new line
      }).toString();

      return res.redirect(`${env.FRONTEND_BASE_URL}/oauth/google#${frag}`);
    }
    // Create session
    const role = u.role as 'user' | 'admin';
    const ttlSec = ttlForRole(role, Boolean(state.remember));

    const sid = ulid();
    const refresh = signRefresh({ sub: String(u.id), sid }, ttlSec);
    const refreshHash = sha256(refresh);
    const ua = req.get('user-agent') ?? null;
    const ip = req.ip ?? null;

    const [row] = await pool.query<RowDataPacket[]>('SELECT NOW() AS now');
    const now = new Date(row[0].now);
    const exp = new Date(now.getTime() + ttlSec * 1000);

    await pool.query(
      `INSERT INTO sessions (id, user_id, refresh_hash, user_agent, ip, remember, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [sid, String(u.id), refreshHash, ua, ip, state.remember ? 1 : 0, exp]
    );

    setRefreshCookie(res, refresh, {
      remember: Boolean(state.remember),
      maxAgeSec: ttlSec,
    });
    const access = signAccess({ sub: String(u.id), role });

    // Minimal user payload for client storage
    const userPayload = {
      id: String(u.id),
      fullName: u.full_name,
      email: u.email,
      phone: u.phone,
      role,
    };

    // Redirect to frontend handler with fragment
    const frag = new URLSearchParams({
      accessToken: access,
      user: Buffer.from(JSON.stringify(userPayload)).toString('base64url'),
      next: state.next || '/account',
      store: state.remember ? 'local' : 'session',
    }).toString();

    return res.redirect(`${env.FRONTEND_BASE_URL}/oauth/google#${frag}`);
  } catch (e) {
    return next(e);
  }
});

/** POST /api/auth/login */
auth.post('/login', loginByIpLimiter, loginByEmailLimiter, async (req, res, next) => {
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

    const role = u.role as 'user' | 'admin';
    const ttlSec = ttlForRole(role, Boolean(remember));
    const sid = ulid();
    const refresh = signRefresh({ sub: String(u.id), sid }, ttlSec);
    const refreshHash = sha256(refresh);

    const [row] = await pool.query<RowDataPacket[]>('SELECT NOW() AS now');
    const now = new Date(row[0].now);
    const exp = new Date(now.getTime() + ttlSec * 1000);

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
        exp,
      ]
    );

    setRefreshCookie(res, refresh, {
      remember: Boolean(remember),
      maxAgeSec: ttlSec,
    });
    const access = signAccess({ sub: String(u.id), role });
    res.json({
      accessToken: access,
      user: {
        id: String(u.id),
        fullName: u.full_name,
        email: u.email,
        phone: u.phone,
        role,
      },
    });
  } catch (e) {
    next(e);
  }
});

auth.post('/mfa/login/verify', mfaVerifyLimiter, async (req, res, next) => {
  try {
    const { challengeId, code } = z
      .object({
        challengeId: z.string().min(10),
        code: z.string().min(4).max(64), // allow both 6-digit and formatted backup codes
      })
      .parse(req.body);

    // Load pending
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
    if (!rec || rec.consumed_at) return res.status(400).json({ error: 'Invalid challenge' });
    if (new Date(rec.expires_at) < new Date())
      return res.status(400).json({ error: 'Challenge expired' });

    const userId = String(rec.user_id);

    // 1) Try TOTP
    let ok = false;
    if (/^\d{6}$/.test(code)) {
      if (!rec.mfa_secret_enc) return res.status(400).json({ error: 'MFA misconfigured' });
      const secretRaw = decryptFromBlob(Buffer.from(rec.mfa_secret_enc));
      ok = verifyTotp(code, secretRaw);
    }

    // 2) If not TOTP, try backup code
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

    if (!ok) return res.status(400).json({ error: 'Invalid code' });

    // Consume pending
    await pool.query(`UPDATE mfa_login_challenges SET consumed_at = NOW() WHERE id = ?`, [
      challengeId,
    ]);

    // Issue real session (same as normal login)
    const role = rec.role as 'user' | 'admin';
    const remember = Boolean(rec.remember);
    const ttlSec = ttlForRole(role, remember);

    const sid = ulid();
    const refresh = signRefresh({ sub: userId, sid }, ttlSec);
    const refreshHash = sha256(refresh);

    const [row] = await pool.query<RowDataPacket[]>('SELECT NOW() AS now');
    const now = new Date(row[0].now);
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
    const access = signAccess({ sub: userId, role });
    res.json({
      accessToken: access,
      user: {
        id: userId,
        fullName: rec.full_name,
        email: rec.email,
        phone: rec.phone,
        role,
      },
    }as AuthOutputDto);
  } catch (e) {
    next(e);
  }
});

/** POST /api/auth/refresh */
auth.post('/refresh', async (req, res, next) => {
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
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
});

/** POST /api/auth/logout */
auth.post('/logout', async (req, res) => {
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
    // clear with matching options so the cookie actually deletes
    res.clearCookie(env.REFRESH_COOKIE_NAME, {
      path: '/api/auth',
      domain: env.COOKIE_DOMAIN || undefined,
      sameSite: 'lax',
      secure: env.NODE_ENV === 'production',
    });
    res.status(204).end();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
});

/** GET /api/auth/me */
auth.get('/me', async (req, res) => {
  const authz = req.get('authorization') || '';
  const token = authz.startsWith('Bearer ') ? authz.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const { sub } = verifyAccess(token);
    const [rows] = await pool.query<RowDataPacket[]>(
      `SELECT id, full_name, email, phone, role, status FROM users WHERE id = ? LIMIT 1`,
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
    });
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
});

// ===== Resend Verification Email =====
auth.post('/verify-email/resend', async (req, res) => {
  try {
    const { email } = ResendVerification.parse(req.body);

    const [rows] = await pool.query<RowDataPacket[]>(
      'SELECT id, email_verified_at FROM users WHERE email = ? LIMIT 1',
      [email.toLowerCase()]
    );
    const u = rows[0];

    // Only send if the user exists AND is not already verified
    if (u && !u.email_verified_at) {
      // We call the same helper function
      void sendNewVerificationEmail(String(u.id), email.toLowerCase());
    }

    // Always return OK to prevent email enumeration
    res.json({ ok: true } as OkResponseDto);
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
});

/** POST /api/auth/forgot */
auth.post('/forgot', async (req, res) => {
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
      const [row] = await pool.query<RowDataPacket[]>('SELECT NOW() AS now');
      const exp = new Date(new Date(row[0].now).getTime() + 60 * 60 * 1000); // 1h
      await pool.query(
        `INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (?, ?, ?)`,
        [String(u.id), hash, exp]
      );
      const resetUrl = `${env.FRONTEND_BASE_URL}/reset-password?token=${token}`;

      try {
        await sendPasswordResetEmail(email.toLowerCase(), resetUrl);

        // You can still keep this for dev logging if you like
        if (env.NODE_ENV === 'development') {
          logger.info({ resetUrl }, 'Password reset link sent');
        }
      } catch (emailError) {
        // Log the error, but do not tell the user.
        // This prevents attackers from knowing if an email failed to send.
        logger.error({ err: emailError, email }, 'Failed to send password reset email');
      }
    }

    // Always send a generic success response
    res.json({ ok: true } as OkResponseDto);
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
});

/** POST /api/auth/reset */
auth.post('/reset', async (req, res) => {
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
    // revoke all sessions for this user
    await pool.query(`UPDATE sessions SET revoked_at = NOW() WHERE user_id = ?`, [
      String(r.user_id),
    ]);
    res.json({ ok: true } as OkResponseDto);
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
});
