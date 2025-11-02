import { bucket } from '../integrations/firebase.js';
import { randomUUID } from 'crypto';

export type UploadSpec = {
  filename: string;
  contentType: string;
  folder?: string;
  ttlSeconds?: number;
};

export async function getSignedUploadUrl({
  filename,
  contentType,
  folder = 'uploads',
  ttlSeconds = 15 * 60,
}: UploadSpec) {
  const id = randomUUID();
  const safeName = String(filename)
    .replace(/\s+/g, '-')
    .toLowerCase()
    .replace(/[^a-z0-9._-]/g, '');
  const objectPath = `${folder}/${id}-${safeName}`;

  const file = bucket.file(objectPath);
  const expires = Date.now() + ttlSeconds * 1000;

  const [url] = await file.getSignedUrl({
    version: 'v4',
    action: 'write',
    expires,
    contentType,
  });

  const publicUrl = `https://storage.googleapis.com/${bucket.name}/${encodeURIComponent(objectPath)}`;
  return { uploadUrl: url, objectPath, publicUrl, expiresAt: new Date(expires).toISOString() };
}
