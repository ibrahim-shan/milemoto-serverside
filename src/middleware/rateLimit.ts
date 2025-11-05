// src/middleware/rateLimit.ts
import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import type { Request } from 'express';
import { env } from '../config/env.js';

const ipOf = (req: Request) => ipKeyGenerator(req.ip ?? req.socket?.remoteAddress ?? '');

export const authLimiter = rateLimit({
  windowMs: env.RATE_AUTH_WINDOW_MS,
  limit: env.RATE_AUTH_MAX,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  keyGenerator: (req) => ipOf(req),
});

export const loginByIpLimiter = rateLimit({
  windowMs: env.RATE_LOGIN_IP_WINDOW_MS,
  limit: env.RATE_LOGIN_IP_MAX,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  keyGenerator: (req) => ipOf(req),
});

export const loginByEmailLimiter = rateLimit({
  windowMs: env.RATE_LOGIN_EMAIL_WINDOW_MS,
  limit: env.RATE_LOGIN_EMAIL_MAX,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  keyGenerator: (req) => {
    const email = (req.body?.email ?? '').toString().trim().toLowerCase();
    return email ? `email:${email}` : 'email:missing';
  },
});

export const uploadsByIpLimiter = rateLimit({
  windowMs: env.RATE_UPLOAD_IP_WINDOW_MS,
  limit: env.RATE_UPLOAD_IP_MAX,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  keyGenerator: (req) => ipOf(req), // IPv6-safe via ipKeyGenerator
});

export const uploadsByUserLimiter = rateLimit({
  windowMs: env.RATE_UPLOAD_USER_WINDOW_MS,
  limit: env.RATE_UPLOAD_USER_MAX,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  keyGenerator: (req) => {
    const uid = req.user?.id;
    // Fallback to IP if somehow missing (shouldn't happen because requireAuth runs first)
    return uid ? `uid:${uid}` : ipOf(req);
  },
});

export const mfaVerifyLimiter = rateLimit({
  windowMs: env.RATE_MFA_WINDOW_MS,
  limit: env.RATE_MFA_MAX,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  keyGenerator: (req) => {
    const ch = (req.body?.challengeId ?? '').toString().trim();
    // Scope primarily by challengeId; fall back to IP if missing
    return ch ? `mfa:${ch}` : ipOf(req);
  },
});
