import { Router } from 'express';
import { getSignedUploadUrl } from '../services/uploader.js';
import { requireAuth } from '../middleware/authz.js';
import { uploadsByIpLimiter, uploadsByUserLimiter } from '../middleware/rateLimit.js';

export const uploads = Router();

function sanitizeFolder(input?: string): string {
  if (!input) return 'uploads';
  // keep alphanum, -, _, / and collapse repeated slashes
  const safe = input
    .replace(/[^a-zA-Z0-9/_-]/g, '')
    .replace(/\/{2,}/g, '/')
    .replace(/^\/+|\/+$/g, '');
  return safe || 'uploads';
}

/**
 * POST /api/uploads/signed
 * Body: { filename: string, contentType: string, folder?: string }
 */
uploads.post(
  '/signed',
  uploadsByIpLimiter,
  uploadsByUserLimiter,
  requireAuth,
  async (req, res, next) => {
    try {
      const { filename, contentType, folder } = req.body || {};
      if (!filename || !contentType)
        return res.status(400).json({ error: 'filename and contentType are required' });

      // Basic allowlist
      if (!/^image\/(webp|jpeg|png|jpg)$/.test(contentType)) {
        return res.status(400).json({ error: 'Unsupported contentType' });
      }

      const data = await getSignedUploadUrl({
        filename,
        contentType,
        folder: sanitizeFolder(folder),
      });
      res.json(data);
    } catch (e) {
      next(e);
    }
  }
);
