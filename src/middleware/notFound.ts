import { Request, Response, NextFunction } from 'express';
export function notFound(
  _req: Request,
  res: Response,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  _next: NextFunction
) {
  res.status(404).json({ error: 'Not Found' });
}
