import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import pinoHttp from 'pino-http';
import crypto from 'crypto';
import { api } from './routes/index.js';
import { notFound } from './middleware/notFound.js';
import { errorHandler } from './middleware/errorHandler.js';
import { logger } from './utils/logger.js';
import { env } from './config/env.js';
import { authLimiter } from './middleware/rateLimit.js';

export const app = express();
app.set('trust proxy', env.TRUST_PROXY);

const allowed = new Set(env.CORS_ORIGINS.split(',').map((s) => s.trim()));

app.use(
  cors({
    origin(origin, cb) {
      if (!origin || allowed.has(origin)) return cb(null, true);
      return cb(new Error('CORS blocked'), false);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-Id'],
    exposedHeaders: ['X-Request-Id'],
  })
);

app.use(
  helmet({
    crossOriginResourcePolicy: { policy: 'cross-origin' },
    contentSecurityPolicy: false,
  })
);

app.use('/api/auth', authLimiter);
app.use('/api/v1/auth', authLimiter);

app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(
  pinoHttp({
    logger,
    genReqId(req) {
      const hdr = (req.headers['x-request-id'] || '').toString();
      return hdr || crypto.randomUUID();
    },
  })
);

// Echo back the request id for clients and correlation in logs
app.use((req, res, next) => {
  const id = req.id;
  if (id && (typeof id === 'string' || typeof id === 'number')) {
    res.setHeader('X-Request-Id', id);
  }

  next();
});

app.get('/', (_req, res) => res.json({ name: 'MileMoto API', version: '0.1.0' }));

app.use('/api', api);

app.use(notFound);
app.use(errorHandler);
