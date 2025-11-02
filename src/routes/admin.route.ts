import { Router } from 'express';
import { requireAuth, requireRole } from '../middleware/authz.js';

export const admin = Router();
admin.use(requireAuth, requireRole('admin')); // all routes below require admin

admin.get('/ping', (_req, res) => {
  res.json({ ok: true, scope: 'admin' });
});
