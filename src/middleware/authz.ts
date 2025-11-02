import type { Request, Response, NextFunction } from 'express';
import { verifyAccess } from '../utils/jwt.js';

const RANK = { user: 1, admin: 2 } as const;
export function requireAtLeast(min: keyof typeof RANK) {
  return (req: Request, res: Response, next: NextFunction) => {
    const u = req.user;
    if (!u) return res.status(401).json({ error: 'No token' });
    if ((RANK[u.role as keyof typeof RANK] ?? 0) < RANK[min])
      return res.status(403).json({ error: 'Forbidden' });
    next();
  };
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const authz = req.get('authorization') || '';
  if (!authz.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
  try {
    const payload = verifyAccess(authz.slice(7));
    req.user = { id: payload.sub, role: payload.role };
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

export function requireRole(role: 'admin' | 'user') {
  return (req: Request, res: Response, next: NextFunction) => {
    const u = req.user;
    if (!u) return res.status(401).json({ error: 'No token' });
    if (u.role !== role) return res.status(403).json({ error: 'Forbidden' });
    next();
  };
}
