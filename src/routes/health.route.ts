import { Router } from 'express';
export const health = Router();

health.get('/', (_req, res) => {
  res.json({ ok: true, service: 'milemoto-serverside', time: new Date().toISOString() });
});
