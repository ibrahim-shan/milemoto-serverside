import { Router } from 'express';
import { z } from 'zod';

import { requireAuth, requireRole } from '../../middleware/authz.js';
import { pool } from '../../db/pool.js';
import type { RowDataPacket, ResultSetHeader } from 'mysql2';

const CompanySchema = z.object({
  name: z.string().min(1).max(191),
  publicEmail: z.string().email().optional().nullable(),
  phone: z.string().max(64).optional().nullable(),
  website: z.string().url().optional().nullable(),
  address: z.string().max(255).optional().nullable(),
  city: z.string().max(191).optional().nullable(),
  state: z.string().max(191).optional().nullable(),
  zip: z.string().max(32).optional().nullable(),
  countryId: z.coerce.number().int().positive().optional().nullable(),
  latitude: z.number().finite().optional().nullable(),
  longitude: z.number().finite().optional().nullable(),
});

type CompanyRow = RowDataPacket & {
  id: number;
  name: string;
  public_email: string | null;
  phone: string | null;
  website: string | null;
  address: string | null;
  city: string | null;
  state: string | null;
  zip: string | null;
  country_id: number | null;
  country_name: string | null;
  country_status: string | null;
  latitude: string | number | null;
  longitude: string | number | null;
  created_at: Date;
  updated_at: Date;
};

const companyAdmin = Router();

companyAdmin.use(requireAuth, requireRole('admin'));

const BASE_SELECT = `
  SELECT
    cp.id,
    cp.name,
    cp.public_email,
    cp.phone,
    cp.website,
    cp.address,
    cp.city,
    cp.state,
    cp.zip,
    cp.country_id,
    co.name AS country_name,
    co.status AS country_status,
    cp.latitude,
    cp.longitude,
    cp.created_at,
    cp.updated_at
  FROM company_profile cp
  LEFT JOIN countries co ON co.id = cp.country_id
  WHERE cp.id = 1
`;

function mapCompanyRow(row: CompanyRow | undefined) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    publicEmail: row.public_email,
    phone: row.phone,
    website: row.website,
    address: row.address,
    city: row.city,
    state: row.state,
    zip: row.zip,
    countryId: row.country_id,
    countryName: row.country_name,
    countryStatus: (row.country_status as 'active' | 'inactive' | null) ?? null,
    latitude: row.latitude !== null ? Number(row.latitude) : null,
    longitude: row.longitude !== null ? Number(row.longitude) : null,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
  };
}

companyAdmin.get('/', async (_req, res, next) => {
  try {
    const [rows] = await pool.query<CompanyRow[]>(BASE_SELECT);
    const row = rows[0];

    if (!row) {
      return res.json(null);
    }
    res.json(mapCompanyRow(row));
  } catch (err) {
    next(err);
  }
});

companyAdmin.put('/', async (req, res, next) => {
  try {
    const payload = CompanySchema.parse(req.body);

    const lat = payload.latitude ?? null;
    const lng = payload.longitude ?? null;
    const countryId = payload.countryId ?? null;

    const fields = {
      name: payload.name,
      public_email: payload.publicEmail ?? null,
      phone: payload.phone ?? null,
      website: payload.website ?? null,
      address: payload.address ?? null,
      city: payload.city ?? null,
      state: payload.state ?? null,
      zip: payload.zip ?? null,
      country_id: countryId,
      latitude: lat,
      longitude: lng,
    };

    const insertSql = `
      INSERT INTO company_profile
        (id, name, public_email, phone, website, address, city, state, zip, country_id, latitude, longitude)
      VALUES
        (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        name = VALUES(name),
        public_email = VALUES(public_email),
        phone = VALUES(phone),
        website = VALUES(website),
        address = VALUES(address),
        city = VALUES(city),
        state = VALUES(state),
        zip = VALUES(zip),
        country_id = VALUES(country_id),
        latitude = VALUES(latitude),
        longitude = VALUES(longitude)
    `;

    await pool.query<ResultSetHeader>(insertSql, [
      fields.name,
      fields.public_email,
      fields.phone,
      fields.website,
      fields.address,
      fields.city,
      fields.state,
      fields.zip,
      fields.country_id,
      fields.latitude,
      fields.longitude,
    ]);

    const [rows] = await pool.query<CompanyRow[]>(BASE_SELECT);
    res.json(mapCompanyRow(rows[0]));
  } catch (err) {
    next(err);
  }
});

export { companyAdmin };
