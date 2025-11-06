import { Router } from 'express';
import { z } from 'zod';
import { requireAuth, requireRole } from '../middleware/authz.js';
import { runtimeFlags } from '../config/runtime.js';
import { logger } from '../utils/logger.js';
import { locationAdmin } from './admin/location.route.js';
import { companyAdmin } from './admin/company.route.js';

export const admin = Router();
admin.use(requireAuth, requireRole('admin')); // all routes below require admin

admin.use('/locations', locationAdmin);
admin.use('/company', companyAdmin);

admin.get('/ping', (_req, res) => {
  res.json({ ok: true, scope: 'admin' });
});

// Runtime toggle: enforce trusted-device fingerprint for all users (admins are always enforced)
admin.get('/security/trusted-devices/fingerprint', (_req, res) => {
  res.json({
    enforceAll: runtimeFlags.trustedDeviceFpEnforceAll,
    enforceAdminsAlways: true,
  });
});

admin.post('/security/trusted-devices/fingerprint', (req, res) => {
  const { enforceAll } = z.object({ enforceAll: z.boolean() }).parse(req.body ?? {});
  const before = runtimeFlags.trustedDeviceFpEnforceAll;
  runtimeFlags.trustedDeviceFpEnforceAll = enforceAll;
  try {
    const adminId = req.user ? String(req.user.id) : 'unknown';
    logger.info(
      { code: 'FingerprintPolicyToggled', adminId, before, after: enforceAll },
      'Updated trusted-device fingerprint policy'
    );
  } catch {}
  res.json({ ok: true, enforceAll });
});
