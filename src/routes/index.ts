import { Router } from 'express';
import { apiV1 } from './v1.js';

export const api = Router();

api.use('/v1', apiV1);
