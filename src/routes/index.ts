import { Router } from 'express';
import { health } from './health.route.js';
import { uploads } from './uploads.route.js';
import { auth } from './auth.route.js';
import { admin } from './admin.route.js';
import { apiV1 } from './v1.js';

export const api = Router();
api.use('/v1', apiV1);
api.use('/health', health);
api.use('/uploads', uploads);
api.use('/auth', auth);
api.use('/admin', admin);
