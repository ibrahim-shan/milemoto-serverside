import { initializeApp, getApps, cert } from 'firebase-admin/app';
import { getStorage } from 'firebase-admin/storage';
import { env } from '../config/env.js';

let key = env.FIREBASE_PRIVATE_KEY.trim();
if ((key.startsWith('"') && key.endsWith('"')) || (key.startsWith("'") && key.endsWith("'"))) {
  key = key.slice(1, -1);
}
key = key.replace(/\\n/g, '\n');

export const firebaseApp =
  getApps()[0] ||
  initializeApp({
    credential: cert({
      projectId: env.FIREBASE_PROJECT_ID,
      clientEmail: env.FIREBASE_CLIENT_EMAIL,
      privateKey: key,
    }),
    storageBucket: env.FIREBASE_STORAGE_BUCKET,
  });

export const bucket = getStorage(firebaseApp).bucket();
