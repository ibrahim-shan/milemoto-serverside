// src/routes/auth/index.ts
import { Router } from 'express';
import { env } from '../../config/env.js';
import { coreAuth } from './core.route.js';
import { passwordAuth } from './password.route.js';
import { mfaAuth } from './mfa.route.js';
import { deviceAuth } from './device.route.js';
import { userAuth } from './user.route.js';
import { oauthAuth } from './oauth.route.js';

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
  if ((!origin && !referer) || allowByOrigin || allowByReferer) return next();
  return res.status(403).json({ error: 'CSRF blocked' });
});

// Assemble all the sub-routers
auth.use(coreAuth);
auth.use(passwordAuth);
auth.use(mfaAuth);
auth.use(deviceAuth);
auth.use(userAuth);
auth.use(oauthAuth);
