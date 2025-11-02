import { Router, type Response } from 'express';
import { auth } from './auth.route.js';
import { health } from './health.route.js';
import { uploads } from './uploads.route.js';
import { admin } from './admin.route.js';

export const apiV1 = Router();

// Normalize error response shape to { code, message, details? } for all v1 routes
apiV1.use((req, res, next) => {
  const originalJson = res.json.bind(res) as Response['json'];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (res as any).json = (body: any) => {
    const status = res.statusCode || 200;
    if (status >= 400 && body && typeof body === 'object') {
      const code = body.code ?? body.error ?? 'Error';
      const message = body.message || (status >= 500 ? 'Internal Server Error' : 'Request failed');
      const details = body.details;
      return originalJson({ code, message, ...(details ? { details } : {}) });
    }
    return originalJson(body as never);
  };
  next();
});

apiV1.use('/health', health);
apiV1.use('/uploads', uploads);
apiV1.use('/auth', auth);
apiV1.use('/admin', admin);
