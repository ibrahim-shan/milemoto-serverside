import { randomBytes, createHash, timingSafeEqual, createCipheriv, createDecipheriv } from 'crypto';
import { env } from '../config/env.js';

/** SHA-256 hex */
export function sha256(input: string | Buffer): string {
  return createHash('sha256').update(input).digest('hex');
}

/** URL-safe random token (base64url, no padding) */
export function randToken(bytes = 32): string {
  return randomBytes(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

/** Decode base64 key from env; must be 32 bytes for AES-256-GCM */
function getMfaKey(): Buffer {
  const key = Buffer.from(env.MFA_SECRET_KEY, 'base64');
  if (key.length !== 32) throw new Error('MFA key must be 32 bytes');
  return key;
}

/**
 * AES-256-GCM encrypt → single blob: [12-byte IV | ciphertext | 16-byte tag]
 * Store as VARBINARY in DB.
 */
export function encryptToBlob(plain: Buffer | Uint8Array): Buffer {
  const key = getMfaKey();
  const iv = randomBytes(12); // GCM 96-bit recommended IV
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, ct, tag]);
}

/** AES-256-GCM decrypt from single blob format above */
export function decryptFromBlob(blob: Buffer): Buffer {
  if (blob.length < 12 + 16) throw new Error('Blob too small');
  const key = getMfaKey();
  const iv = blob.subarray(0, 12);
  const tag = blob.subarray(blob.length - 16);
  const ct = blob.subarray(12, blob.length - 16);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

/** Constant-time compare for buffers/strings */
export function safeEquals(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  try {
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}
