import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';

type Role = 'user' | 'admin';
type AccessPayload = { sub: string; role: Role };
type RefreshPayload = { sub: string; sid: string };

export function signAccess(payload: AccessPayload): string {
  return jwt.sign(payload, env.JWT_ACCESS_SECRET, { expiresIn: env.ACCESS_TOKEN_TTL_SEC });
}
export function signRefresh(
  payload: RefreshPayload,
  ttlSec = env.USER_REFRESH_TOKEN_TTL_SEC
): string {
  return jwt.sign(payload, env.JWT_REFRESH_SECRET, { expiresIn: ttlSec });
}

export function verifyAccess(token: string): AccessPayload {
  return jwt.verify(token, env.JWT_ACCESS_SECRET) as AccessPayload;
}
export function verifyRefresh(token: string): RefreshPayload {
  return jwt.verify(token, env.JWT_REFRESH_SECRET) as RefreshPayload;
}
