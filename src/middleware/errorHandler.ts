import type { Request, Response, NextFunction } from 'express';
import { ZodError } from 'zod';

export function errorHandler(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  err: any,
  req: Request,
  res: Response,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  _next: NextFunction
) {
  const isV1 = (req.originalUrl || '').startsWith('/api/v1/');
  if (err instanceof ZodError) {
    if (isV1)
      return res
        .status(400)
        .json({ code: 'ValidationError', message: 'Invalid request', details: err.flatten() });
    return res.status(400).json({ error: 'ValidationError', details: err.flatten() });
  }
  const status = Number(err?.status) || 500;
  const code = err?.code || 'InternalError';
  const message = status >= 500 ? 'Internal Server Error' : err?.message || 'Request failed';
  if (isV1)
    return res
      .status(status)
      .json({ code, message, ...(err?.details ? { details: err.details } : {}) });
  return res.status(status).json({ error: code, message });
}
