import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';
import { z } from 'zod';

const __dirname = dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: resolve(__dirname, '../../.env') });

const Env = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().default(4000),

  MYSQL_HOST: z.string(),
  MYSQL_PORT: z.coerce.number().default(3306),
  MYSQL_USER: z.string(),
  MYSQL_PASSWORD: z.string().optional().default(''),
  MYSQL_DATABASE: z.string(),

  GOOGLE_CLIENT_ID: z.string(),
  GOOGLE_CLIENT_SECRET: z.string(),
  OAUTH_STATE_SECRET: z.string().min(32),

  PRICE_CURRENCY: z.literal('USD').default('USD'),

  FIREBASE_PROJECT_ID: z.string(),
  FIREBASE_CLIENT_EMAIL: z.string(),
  FIREBASE_PRIVATE_KEY: z.string(),
  FIREBASE_STORAGE_BUCKET: z.string(),

  SENDGRID_API_KEY: z.string().optional(),

  JWT_ACCESS_SECRET: z.string(),
  JWT_REFRESH_SECRET: z.string(),
  ACCESS_TOKEN_TTL_SEC: z.coerce.number().default(900),

  // remember=true (persistent cookie) TTLs
  USER_REFRESH_TOKEN_TTL_SEC: z.coerce.number().default(2592000), // users: 30d
  ADMIN_REFRESH_TOKEN_TTL_SEC: z.coerce.number().default(86400), // admins: 1d

  // remember=false (session cookie) TTLs
  USER_SESSION_REFRESH_TTL_SEC: z.coerce.number().default(86400), // 1d
  ADMIN_SESSION_REFRESH_TTL_SEC: z.coerce.number().default(43200), // 12h

  REFRESH_COOKIE_NAME: z.string().default('mm_refresh'),

  FRONTEND_BASE_URL: z.string().url().default('http://localhost:3000'),
  CORS_ORIGINS: z.string().default('http://localhost:3000'),
  COOKIE_DOMAIN: z.string().optional(),
  TRUST_PROXY: z.coerce.number().default(1),

  MFA_SECRET_KEY: z
    .string()
    .refine(
      (v) => Buffer.from(v, 'base64').length === 32,
      'MFA_SECRET_KEY must be base64 32 bytes'
    ),
  BACKUP_CODE_HMAC_SECRET: z.string().min(32),
  TRUSTED_DEVICE_TTL_DAYS: z.coerce.number().default(30),
  TRUSTED_DEVICE_FINGERPRINT_ENABLED: z.coerce.boolean().default(false),
  TOTP_STEP_SEC: z.coerce.number().default(30), // 30s window (RFC 6238)
  TOTP_WINDOW_STEPS: z.coerce.number().default(1), // ±1 step tolerance
  MFA_CHALLENGE_TTL_SEC: z.coerce.number().default(600), // setup QR validity (10m)
  MFA_LOGIN_TTL_SEC: z.coerce.number().default(300), // pending login validity (5m)

  RATE_AUTH_WINDOW_MS: z.coerce.number().default(60_000),
  RATE_AUTH_MAX: z.coerce.number().default(120),
  RATE_LOGIN_IP_WINDOW_MS: z.coerce.number().default(15 * 60_000),
  RATE_LOGIN_IP_MAX: z.coerce.number().default(10),
  RATE_LOGIN_EMAIL_WINDOW_MS: z.coerce.number().default(15 * 60_000),
  RATE_LOGIN_EMAIL_MAX: z.coerce.number().default(5),
  RATE_UPLOAD_IP_WINDOW_MS: z.coerce.number().default(60_000),
  RATE_UPLOAD_IP_MAX: z.coerce.number().default(30),
  RATE_UPLOAD_USER_WINDOW_MS: z.coerce.number().default(60_000),
  RATE_UPLOAD_USER_MAX: z.coerce.number().default(20),
  RATE_MFA_WINDOW_MS: z.coerce.number().default(10 * 60_000),
  RATE_MFA_MAX: z.coerce.number().default(6),
});

export const env = Env.parse(process.env);
