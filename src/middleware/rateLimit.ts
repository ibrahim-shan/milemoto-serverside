// src/middleware/rateLimit.ts
import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import type { Request } from 'express';

const ipOf = (req: Request) => ipKeyGenerator(req.ip ?? req.socket?.remoteAddress ?? '');

export const authLimiter = rateLimit({
  windowMs: 60_000,
  limit: 120,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  keyGenerator: (req) => ipOf(req),
});

export const loginByIpLimiter = rateLimit({
  windowMs: 15 * 60_000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  keyGenerator: (req) => ipOf(req),
});

export const loginByEmailLimiter = rateLimit({
  windowMs: 15 * 60_000,
  limit: 5,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  keyGenerator: (req) => {
    const email = (req.body?.email ?? '').toString().trim().toLowerCase();
    return email ? `email:${email}` : 'email:missing';
  },
});

export const uploadsByIpLimiter = rateLimit({
  windowMs: 60_000, // 1 minute bucket
  limit: 30, // max 30 signed URLs / min per IP
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  keyGenerator: (req) => ipOf(req), // IPv6-safe via ipKeyGenerator
});

export const uploadsByUserLimiter = rateLimit({
  windowMs: 60_000, // 1 minute bucket
  limit: 20, // max 20 signed URLs / min per user
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  keyGenerator: (req) => {
    const uid = req.user?.id;
    // Fallback to IP if somehow missing (shouldn't happen because requireAuth runs first)
    return uid ? `uid:${uid}` : ipOf(req);
  },
});

export const mfaVerifyLimiter = rateLimit({
  windowMs: 10 * 60_000, // 10 minutes
  limit: 6, // max 6 attempts per challenge window
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  keyGenerator: (req) => {
    const ch = (req.body?.challengeId ?? '').toString().trim();
    // Scope primarily by challengeId; fall back to IP if missing
    return ch ? `mfa:${ch}` : ipOf(req);
  },
});
