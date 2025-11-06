// src/routes/auth/oauth.route.ts
import { Router } from 'express';
import argon2 from 'argon2';
import crypto from 'crypto';
import { pool } from '../../db/pool.js';
import { signAccess, signRefresh } from '../../utils/jwt.js';
import { logger } from '../../utils/logger.js';
import { env } from '../../config/env.js';
import { ulid } from 'ulid';
import { ResultSetHeader, RowDataPacket } from 'mysql2';
import type { UserAuthData } from '@milemoto/types';
import {
  safeNext,
  verifyState,
  signState,
  validateTrustedCookie,
  ttlForRole,
  setRefreshCookie,
} from './auth.helpers.js';
import { sha256 } from '../../utils/crypto.js';
import { dbNow } from '../../db/time.js';

export const oauthAuth = Router();

oauthAuth.get('/google/start', (req, res) => {
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

oauthAuth.get('/google/callback', async (req, res, next) => {
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

    // Decode id_token
    const parts = tok.id_token.split('.');
    if (parts.length < 2 || !parts[1]) return res.status(400).send('Bad id_token');
    const payloadB64 = parts[1];
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

    // Minimal claim checks
    const nowSec = Math.floor(Date.now() / 1000);
    const validIssuer =
      info.iss === 'https://accounts.google.com' || info.iss === 'accounts.google.com';

    if (!validIssuer) return res.status(400).send('Bad iss');
    if (info.aud !== env.GOOGLE_CLIENT_ID) return res.status(400).send('Bad aud');
    if (typeof info.exp !== 'number' || info.exp <= nowSec)
      return res.status(400).send('Token expired');
    if (info.email_verified !== true) return res.status(400).send('Email not verified');

    const gsub = info.sub;
    const emailRaw = info.email || '';
    if (!emailRaw) return res.status(400).send('Google account missing email');
    const email = emailRaw.toLowerCase();

    const nameStr = (info.name?.trim() ||
      `${info.given_name ?? ''} ${info.family_name ?? ''}`.trim() ||
      email.split('@')[0]) as string;

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
      // Create user
      const randomPw = crypto.randomBytes(16).toString('hex');
      const hash = await argon2.hash(randomPw, { type: argon2.argon2id });
      const [ins] = await pool.query<ResultSetHeader>(
        `INSERT INTO users (full_name, email, password_hash, role, status, email_verified_at, google_sub)
         VALUES (?, ?, ?, 'user', 'active', ?, ?)`,
        [nameStr, email, hash, info.email_verified ? new Date() : null, gsub]
      );
      const userId = String(ins.insertId);
      u = {
        id: userId,
        full_name: nameStr,
        email,
        phone: null,
        role: 'user',
        status: 'active',
        mfa_enabled: 0,
        email_verified_at: info.email_verified ? new Date() : null,
      };
    }
    if (!u) return res.status(500).send('User resolution failed');

    if (!u.email_verified_at) {
      return res.redirect(`${env.FRONTEND_BASE_URL}/signin?error=EmailNotVerified`);
    }

    if (u.mfa_enabled) {
      // MFA logic
      try {
        const isTrusted = await validateTrustedCookie(
          req,
          String(u.id),
          u.role as 'user' | 'admin'
        );
        if (isTrusted) {
          // ... (full logic for trusted device login, same as in core.route.ts)
          const role = u.role as 'user' | 'admin';
          const ttlSec = ttlForRole(role, Boolean(state.remember));
          const sid = ulid();
          const refresh = signRefresh({ sub: String(u.id), sid }, ttlSec);
          // ... (create session, set cookie, etc.)
          const refreshHash = sha256(refresh);
          const ua = req.get('user-agent') ?? null;
          const ip = req.ip ?? null;
          const now = await dbNow();
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
          const userPayload = {
            id: String(u.id),
            fullName: u.full_name,
            email: u.email,
            phone: u.phone,
            role,
          };
          const frag = new URLSearchParams({
            accessToken: access,
            user: Buffer.from(
              JSON.stringify({ ...userPayload, mfaEnabled: Boolean(u.mfa_enabled) })
            ).toString('base64url'),
            next: state.next || '/account',
            store: state.remember ? 'local' : 'session',
          }).toString();
          return res.redirect(`${env.FRONTEND_BASE_URL}/oauth/google#${frag}`);
        }
      } catch (e) {
        logger.warn({ e, userId: String(u.id) }, 'Google trusted-device bypass failed');
      }

      // MFA challenge
      const pendingId = ulid();
      const now = await dbNow();
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
      const frag = new URLSearchParams({
        mfaRequired: '1',
        challengeId: pendingId,
        expiresAt: exp.toISOString(),
        store: state.remember ? 'local' : 'session',
        next: state.next || '/account',
      }).toString();
      return res.redirect(`${env.FRONTEND_BASE_URL}/oauth/google#${frag}`);
    }

    // No MFA: Create session
    const role = u.role as 'user' | 'admin';
    const ttlSec = ttlForRole(role, Boolean(state.remember));
    const sid = ulid();
    const refresh = signRefresh({ sub: String(u.id), sid }, ttlSec);
    const refreshHash = sha256(refresh);
    const ua = req.get('user-agent') ?? null;
    const ip = req.ip ?? null;
    const now = await dbNow();
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

    const userPayload = {
      id: String(u.id),
      fullName: u.full_name,
      email: u.email,
      phone: u.phone,
      role,
    };

    const frag = new URLSearchParams({
      accessToken: access,
      user: Buffer.from(
        JSON.stringify({ ...userPayload, mfaEnabled: Boolean(u.mfa_enabled) })
      ).toString('base64url'),
      next: state.next || '/account',
      store: state.remember ? 'local' : 'session',
    }).toString();

    return res.redirect(`${env.FRONTEND_BASE_URL}/oauth/google#${frag}`);
  } catch (e) {
    return next(e);
  }
});
