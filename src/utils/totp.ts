// src/utils/totp.ts
import { createHmac, randomBytes } from 'crypto';
import { env } from '../config/env.js';

/** Crockford/RFC4648 Base32 alphabet (no padding) */
const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Base32 encode (buffer → uppercase no padding) */
export function base32Encode(buf: Buffer): string {
  let bits = 0,
    value = 0,
    output = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += B32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

/** Base32 decode (uppercase/lowercase, ignores '=') */
export function base32Decode(b32: string): Buffer {
  let bits = 0,
    value = 0;
  const out: number[] = [];
  for (const ch of b32.toUpperCase()) {
    if (ch === '=') continue;
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** Generate a new random TOTP secret (160-bit) */
export function generateTotpSecret(bytes = 20): Buffer {
  return randomBytes(bytes);
}

/** RFC 6238 TOTP (HMAC-SHA1, 6 digits by default) */
export function totpCode(secret: Buffer, time = Date.now()): string {
  const step = Number(env.TOTP_STEP_SEC);
  const counter = Math.floor(time / 1000 / step);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const hmac = createHmac('sha1', secret).update(msg).digest();

  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const mod = 1_000_000; // 6 digits
  return String(bin % mod).padStart(6, '0');
}

/** Verify within ±window steps */
export function verifyTotp(code: string, secret: Buffer, time = Date.now()): boolean {
  if (!/^\d{6}$/.test(String(code))) return false;
  const window = Number(env.TOTP_WINDOW_STEPS);
  const step = Number(env.TOTP_STEP_SEC);
  for (let w = -window; w <= window; w++) {
    const t = time + w * step * 1000;
    if (totpCode(secret, t) === code) return true;
  }
  return false;
}

/** Build otpauth URI for authenticator apps */
export function otpauthURL(opts: {
  issuer: string;
  account: string;
  secretBase32: string;
  digits?: 6 | 7 | 8;
  period?: number;
  algorithm?: 'SHA1';
}): string {
  const issuer = encodeURIComponent(opts.issuer);
  const account = encodeURIComponent(opts.account);
  const params = new URLSearchParams({
    secret: opts.secretBase32,
    issuer,
    algorithm: opts.algorithm ?? 'SHA1',
    digits: String(opts.digits ?? 6),
    period: String(opts.period ?? Number(env.TOTP_STEP_SEC)),
  });
  return `otpauth://totp/${issuer}:${account}?${params.toString()}`;
}

/** Generate 10 backup codes + hashes (sha256 hex). Printable like XXXX-XXXX */
export function generateBackupCodes(count = 10) {
  const codes: string[] = [];
  const hashes: string[] = [];
  for (let i = 0; i < count; i++) {
    const raw = randomBytes(5).toString('hex').toUpperCase(); // 10 hex chars
    const pretty = `${raw.slice(0, 4)}-${raw.slice(4, 8)}${raw.slice(8)}`; // e.g., ABCD-EF12-3
    codes.push(pretty);
    const h = createHmac('sha256', 'mm-bc-v1').update(pretty).digest('hex'); // domain-separated hash
    hashes.push(h);
  }
  return { codes, hashes };
}
