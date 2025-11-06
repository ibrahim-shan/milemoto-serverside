import { Router } from 'express';
import { requireAuth, requireRole } from '../../middleware/authz.js';
import { uploadJson } from '../../middleware/uploader.js';
import { z } from 'zod';
import { pool } from '../../db/pool.js';
import {
  CreateCountry,
  ListQuery,
  UpdateCountry,
  CreateState,
  UpdateState,
  CreateCity,
  UpdateCity,
  ImportCountries,
} from './location.helpers.js';
import { ResultSetHeader, RowDataPacket } from 'mysql2';

// Create a new router instance for location-related admin endpoints
export const locationAdmin = Router();

// Apply security middleware to ALL routes defined in this file
locationAdmin.use(requireAuth, requireRole('admin'));

// ==== COUNTRIES =================================================

/**
 * CREATE: POST /api/v1/admin/locations/countries
 * Create a new country
 */
locationAdmin.post('/countries', async (req, res, next) => {
  try {
    const { name, code, status } = CreateCountry.parse(req.body);

    const [result] = await pool.query<ResultSetHeader>(
      'INSERT INTO countries (name, code, status) VALUES (?, ?, ?)',
      [name, code, status]
    );

    res.status(201).json({
      id: result.insertId,
      name,
      code,
      status,
    });
  } catch (e) {
    next(e);
  }
});

/**
 * READ: GET /api/v1/admin/locations/countries
 * List countries with pagination and search
 */
locationAdmin.get('/countries', async (req, res, next) => {
  try {
    const { search, page, limit } = ListQuery.parse(req.query);
    const offset = (page - 1) * limit;
    const searchPattern = `%${search}%`;

    const whereClauses = [];
    const params: (string | number)[] = [];

    if (search) {
      whereClauses.push('(name LIKE ? OR code LIKE ?)');
      params.push(searchPattern, searchPattern);
    }

    const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

    // 1. Get total count for pagination
    const [countRows] = await pool.query<RowDataPacket[]>(
      `SELECT COUNT(id) as totalCount FROM countries ${whereSql}`,
      params
    );
    const totalCount = countRows[0]?.totalCount || 0;

    // 2. Get items for the current page
    params.push(limit, offset);
    const [items] = await pool.query<RowDataPacket[]>(
      `SELECT id, name, code, status, created_at, updated_at
       FROM countries
       ${whereSql}
       ORDER BY name ASC
       LIMIT ? OFFSET ?`,
      params
    );

    res.json({
      items,
      totalCount,
    });
  } catch (e) {
    next(e);
  }
});

/**
 * UPDATE: POST /api/v1/admin/locations/countries/:id
 * Update an existing country
 */
locationAdmin.post('/countries/:id', async (req, res, next) => {
  try {
    const countryId = z.coerce.number().int().min(1).parse(req.params.id);
    const body = UpdateCountry.parse(req.body);

    if (Object.keys(body).length === 0) {
      return res.status(400).json({
        code: 'ValidationError',
        message: 'At least one field to update must be provided',
      });
    }

    // Build the SET clause dynamically to avoid overwriting fields with undefined
    const fields: string[] = [];
    const values: (string | number)[] = [];
    for (const [key, value] of Object.entries(body)) {
      if (value !== undefined) {
        fields.push(`${key} = ?`);
        values.push(value);
      }
    }
    values.push(countryId);

    const [result] = await pool.query<ResultSetHeader>(
      `UPDATE countries SET ${fields.join(', ')} WHERE id = ?`,
      values
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ code: 'NotFound', message: 'Country not found' });
    }

    // Return the updated record
    const [rows] = await pool.query<RowDataPacket[]>('SELECT * FROM countries WHERE id = ?', [
      countryId,
    ]);
    res.json(rows[0]);
  } catch (e) {
    next(e);
  }
});

/**
 * DELETE: DELETE /api/v1/admin/locations/countries/:id
 * Delete a country
 */
locationAdmin.delete('/countries/:id', async (req, res, next) => {
  try {
    const countryId = z.coerce.number().int().min(1).parse(req.params.id);

    const [result] = await pool.query<ResultSetHeader>('DELETE FROM countries WHERE id = ?', [
      countryId,
    ]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ code: 'NotFound', message: 'Country not found' });
    }

    res.status(204).end(); // No Content
  } catch (e: unknown) {
    // Handle foreign key constraint errors (e.g., country has states)
    if (e && typeof e === 'object' && 'code' in e && e.code === 'ER_ROW_IS_REFERENCED_2') {
      return res.status(400).json({
        code: 'DeleteFailed',
        message: 'Cannot delete country. It is already linked to existing states.',
      });
    }
    next(e);
  }
});

// ==== SUPPORTING ENDPOINTS (Step 4) ==============================

/**
 * GET /api/v1/admin/locations/countries/all
 * Get a simple list of all active countries (for dropdowns)
 */
locationAdmin.get('/countries/all', async (req, res, next) => {
  try {
    const [items] = await pool.query<RowDataPacket[]>(
      "SELECT id, name FROM countries WHERE status = 'active' ORDER BY name ASC"
    );
    res.json({ items });
  } catch (e) {
    next(e);
  }
});

// ==== STATES ====================================================

/**
 * CREATE: POST /api/v1/admin/locations/states
 * Create a new state
 */
locationAdmin.post('/states', async (req, res, next) => {
  try {
    const { name, country_id, status } = CreateState.parse(req.body);

    const [result] = await pool.query<ResultSetHeader>(
      'INSERT INTO states (name, country_id, status) VALUES (?, ?, ?)',
      [name, country_id, status]
    );

    res.status(201).json({
      id: result.insertId,
      name,
      country_id,
      status,
    });
  } catch (e) {
    next(e);
  }
});

/**
 * READ: GET /api/v1/admin/locations/states
 * List states with pagination and search
 */
locationAdmin.get('/states', async (req, res, next) => {
  try {
    const { search, page, limit } = ListQuery.parse(req.query);
    const offset = (page - 1) * limit;
    const searchPattern = `%${search}%`;

    const whereClauses = [];
    // Note: We use 's.' and 'c.' aliases for the tables
    const params: (string | number)[] = [];

    if (search) {
      // Search by state name OR country name
      whereClauses.push('(s.name LIKE ? OR c.name LIKE ?)');
      params.push(searchPattern, searchPattern);
    }

    const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';
    const baseQuery = 'FROM states s JOIN countries c ON s.country_id = c.id';

    // 1. Get total count for pagination
    const [countRows] = await pool.query<RowDataPacket[]>(
      `SELECT COUNT(s.id) as totalCount ${baseQuery} ${whereSql}`,
      params
    );
    const totalCount = countRows[0]?.totalCount || 0;

    // 2. Get items for the current page
    params.push(limit, offset);
    const [items] = await pool.query<RowDataPacket[]>(
      `SELECT
         s.id, s.name, s.status, s.created_at, s.updated_at,
         c.id as country_id, c.name as country_name
       ${baseQuery}
       ${whereSql}
       ORDER BY s.name ASC
       LIMIT ? OFFSET ?`,
      params
    );

    res.json({
      items,
      totalCount,
    });
  } catch (e) {
    next(e);
  }
});

/**
 * UPDATE: POST /api/v1/admin/locations/states/:id
 * Update an existing state
 */
locationAdmin.post('/states/:id', async (req, res, next) => {
  try {
    const stateId = z.coerce.number().int().min(1).parse(req.params.id);
    const body = UpdateState.parse(req.body);

    if (Object.keys(body).length === 0) {
      return res.status(400).json({
        code: 'ValidationError',
        message: 'At least one field to update must be provided',
      });
    }

    const fields: string[] = [];
    const values: (string | number)[] = [];
    for (const [key, value] of Object.entries(body)) {
      if (value !== undefined) {
        fields.push(`${key} = ?`);
        values.push(value);
      }
    }
    values.push(stateId);

    const [result] = await pool.query<ResultSetHeader>(
      `UPDATE states SET ${fields.join(', ')} WHERE id = ?`,
      values
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ code: 'NotFound', message: 'State not found' });
    }

    // Return the updated record
    const [rows] = await pool.query<RowDataPacket[]>('SELECT * FROM states WHERE id = ?', [
      stateId,
    ]);
    res.json(rows[0]);
  } catch (e) {
    next(e);
  }
});

/**
 * DELETE: DELETE /api/v1/admin/locations/states/:id
 * Delete a state
 */
locationAdmin.delete('/states/:id', async (req, res, next) => {
  try {
    const stateId = z.coerce.number().int().min(1).parse(req.params.id);

    const [result] = await pool.query<ResultSetHeader>('DELETE FROM states WHERE id = ?', [
      stateId,
    ]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ code: 'NotFound', message: 'State not found' });
    }

    res.status(204).end(); // No Content
  } catch (e: unknown) {
    // Handle foreign key constraint errors (e.g., state has cities)
    if (e && typeof e === 'object' && 'code' in e && e.code === 'ER_ROW_IS_REFERENCED_2') {
      return res.status(400).json({
        code: 'DeleteFailed',
        message: 'Cannot delete state. It is already linked to existing cities.',
      });
    }
    next(e);
  }
});

/**
 * GET /api/v1/admin/locations/states/all
 * Get a simple list of all active states (for dropdowns)
 */
locationAdmin.get('/states/all', async (req, res, next) => {
  try {
    const [items] = await pool.query<RowDataPacket[]>(
      "SELECT id, name FROM states WHERE status = 'active' ORDER BY name ASC"
    );
    res.json({ items });
  } catch (e) {
    next(e);
  }
});

// ==== CITIES ====================================================

/**
 * CREATE: POST /api/v1/admin/locations/cities
 * Create a new city
 */
locationAdmin.post('/cities', async (req, res, next) => {
  try {
    const { name, state_id, status } = CreateCity.parse(req.body);

    const [result] = await pool.query<ResultSetHeader>(
      'INSERT INTO cities (name, state_id, status) VALUES (?, ?, ?)',
      [name, state_id, status]
    );

    res.status(201).json({
      id: result.insertId,
      name,
      state_id,
      status,
    });
  } catch (e) {
    next(e);
  }
});

/**
 * READ: GET /api/v1/admin/locations/cities
 * List cities with pagination and search
 */
locationAdmin.get('/cities', async (req, res, next) => {
  try {
    const { search, page, limit } = ListQuery.parse(req.query);
    const offset = (page - 1) * limit;
    const searchPattern = `%${search}%`;

    // Aliases: ci = cities, s = states, co = countries
    const whereClauses = [];
    const params: (string | number)[] = [];

    if (search) {
      // Search by city name, state name, OR country name
      whereClauses.push('(ci.name LIKE ? OR s.name LIKE ? OR co.name LIKE ?)');
      params.push(searchPattern, searchPattern, searchPattern);
    }

    const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';
    const baseQuery = `
       FROM cities ci
       JOIN states s ON ci.state_id = s.id
       JOIN countries co ON s.country_id = co.id
    `;

    // 1. Get total count for pagination
    const [countRows] = await pool.query<RowDataPacket[]>(
      `SELECT COUNT(ci.id) as totalCount ${baseQuery} ${whereSql}`,
      params
    );
    const totalCount = countRows[0]?.totalCount || 0;

    // 2. Get items for the current page
    params.push(limit, offset);
    const [items] = await pool.query<RowDataPacket[]>(
      `SELECT
         ci.id, ci.name, ci.status, ci.created_at,
         s.id as state_id, s.name as state_name,
         co.id as country_id, co.name as country_name
       ${baseQuery}
       ${whereSql}
       ORDER BY ci.name ASC
       LIMIT ? OFFSET ?`,
      params
    );

    res.json({
      items,
      totalCount,
    });
  } catch (e) {
    next(e);
  }
});

/**
 * UPDATE: POST /api/v1/admin/locations/cities/:id
 * Update an existing city
 */
locationAdmin.post('/cities/:id', async (req, res, next) => {
  try {
    const cityId = z.coerce.number().int().min(1).parse(req.params.id);
    const body = UpdateCity.parse(req.body);

    if (Object.keys(body).length === 0) {
      return res.status(400).json({
        code: 'ValidationError',
        message: 'At least one field to update must be provided',
      });
    }

    const fields: string[] = [];
    const values: (string | number)[] = [];
    for (const [key, value] of Object.entries(body)) {
      if (value !== undefined) {
        fields.push(`${key} = ?`);
        values.push(value);
      }
    }
    values.push(cityId);

    const [result] = await pool.query<ResultSetHeader>(
      `UPDATE cities SET ${fields.join(', ')} WHERE id = ?`,
      values
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ code: 'NotFound', message: 'City not found' });
    }

    // Return the updated record
    const [rows] = await pool.query<RowDataPacket[]>('SELECT * FROM cities WHERE id = ?', [cityId]);
    res.json(rows[0]);
  } catch (e) {
    next(e);
  }
});

/**
 * DELETE: DELETE /api/v1/admin/locations/cities/:id
 * Delete a city
 */
locationAdmin.delete('/cities/:id', async (req, res, next) => {
  try {
    const cityId = z.coerce.number().int().min(1).parse(req.params.id);

    const [result] = await pool.query<ResultSetHeader>('DELETE FROM cities WHERE id = ?', [cityId]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ code: 'NotFound', message: 'City not found' });
    }

    res.status(204).end(); // No Content
  } catch (e: unknown) {
    // This table has no foreign keys pointing to it,
    // so we don't need to check for constraint errors.
    next(e);
  }
});

// ==== IMPORT / EXPORT ===========================================

// --- Countries Import/Export ---

locationAdmin.get('/countries/export', async (req, res, next) => {
  try {
    const filename = `export-countries-${new Date().toISOString().split('T')[0]}.json`;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    // Fetch all rows at once using the promise-based API
    const [rows] = await pool.query('SELECT name, code, status FROM countries');
    res.json(rows); // Send the complete JSON array
  } catch (e) {
    next(e);
  }
});

locationAdmin.post('/countries/import', uploadJson.single('file'), async (req, res, next) => {
  // ... (This endpoint was correct and remains unchanged) ...
  try {
    if (!req.file) {
      return res.status(400).json({ code: 'FileRequired', message: 'No JSON file uploaded' });
    }

    const json = JSON.parse(req.file.buffer.toString('utf-8'));
    const rows = ImportCountries.parse(json);

    if (rows.length === 0) {
      return res.status(400).json({ code: 'EmptyFile', message: 'Import file is empty' });
    }

    const values = rows.map((row) => [row.name, row.code, row.status]);

    const [result] = await pool.query<ResultSetHeader>(
      `INSERT INTO countries (name, code, status) VALUES ?
       ON DUPLICATE KEY UPDATE
         name = VALUES(name),
         status = VALUES(status)`,
      [values]
    );

    res.status(201).json({
      message: 'Import successful',
      affectedRows: result.affectedRows,
    });
  } catch (e) {
    next(e);
  }
});

// --- States Import/Export ---

locationAdmin.get('/states/export', async (req, res, next) => {
  try {
    const filename = `export-states-${new Date().toISOString().split('T')[0]}.json`;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    // Fetch all rows at once
    const [rows] = await pool.query(
      `SELECT s.name, c.code as country_code, s.status
       FROM states s
       JOIN countries c ON s.country_id = c.id`
    );
    res.json(rows);
  } catch (e) {
    next(e);
  }
});

locationAdmin.post('/states/import', uploadJson.single('file'), async (req, res, next) => {
  // ... (This endpoint was correct and remains unchanged) ...
  const conn = await pool.getConnection();
  try {
    if (!req.file) {
      return res.status(400).json({ code: 'FileRequired', message: 'No JSON file uploaded' });
    }

    const json = JSON.parse(req.file.buffer.toString('utf-8'));
    const importSchema = z.array(
      z.object({
        name: z.string().min(2),
        country_code: z.string().min(2),
        status: z.enum(['active', 'inactive']),
      })
    );
    const rows = importSchema.parse(json);
    if (rows.length === 0) {
      return res.status(400).json({ code: 'EmptyFile', message: 'Import file is empty' });
    }

    await conn.beginTransaction();

    const [countryRows] = await conn.query<RowDataPacket[]>(
      'SELECT id, code FROM countries WHERE code IN (?)',
      [rows.map((r) => r.country_code)]
    );
    const countryMap = new Map(countryRows.map((r) => [r.code, r.id]));

    const values = rows.map((row) => {
      const countryId = countryMap.get(row.country_code);
      if (!countryId) {
        throw new Error(`Invalid country_code: ${row.country_code}`);
      }
      return [row.name, countryId, row.status];
    });

    const [result] = await conn.query<ResultSetHeader>(
      'INSERT INTO states (name, country_id, status) VALUES ?',
      [values]
    );

    await conn.commit();
    res.status(201).json({
      message: 'Import successful',
      affectedRows: result.affectedRows,
    });
  } catch (e) {
    await conn.rollback();
    next(e);
  } finally {
    conn.release();
  }
});

// --- Cities Import/Export ---

locationAdmin.get('/cities/export', async (req, res, next) => {
  try {
    const filename = `export-cities-${new Date().toISOString().split('T')[0]}.json`;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    // Fetch all rows at once
    const [rows] = await pool.query(
      `SELECT ci.name, s.name as state_name, c.code as country_code, ci.status
       FROM cities ci
       JOIN states s ON ci.state_id = s.id
       JOIN countries c ON s.country_id = c.id`
    );
    res.json(rows);
  } catch (e) {
    next(e);
  }
});

locationAdmin.post('/cities/import', uploadJson.single('file'), async (req, res, next) => {
  // ... (This endpoint was correct and remains unchanged) ...
  const conn = await pool.getConnection();
  try {
    if (!req.file) {
      return res.status(400).json({ code: 'FileRequired', message: 'No JSON file uploaded' });
    }

    const json = JSON.parse(req.file.buffer.toString('utf-8'));
    const importSchema = z.array(
      z.object({
        name: z.string().min(2),
        state_name: z.string().min(2),
        country_code: z.string().min(2),
        status: z.enum(['active', 'inactive']),
      })
    );
    const rows = importSchema.parse(json);
    if (rows.length === 0) {
      return res.status(400).json({ code: 'EmptyFile', message: 'Import file is empty' });
    }

    await conn.beginTransaction();

    const [stateRows] = await conn.query<RowDataPacket[]>(
      `SELECT s.id, s.name, c.code
       FROM states s
       JOIN countries c ON s.country_id = c.id`,
      []
    );
    const stateMap = new Map(stateRows.map((r) => [`${r.name}|${r.code}`, r.id]));

    const values = rows.map((row) => {
      const stateId = stateMap.get(`${row.state_name}|${row.country_code}`);
      if (!stateId) {
        throw new Error(`Invalid combo: state=${row.state_name}, country=${row.country_code}`);
      }
      return [row.name, stateId, row.status];
    });

    const [result] = await conn.query<ResultSetHeader>(
      'INSERT INTO cities (name, state_id, status) VALUES ?',
      [values]
    );

    await conn.commit();
    res.status(201).json({
      message: 'Import successful',
      affectedRows: result.affectedRows,
    });
  } catch (e) {
    await conn.rollback();
    next(e);
  } finally {
    conn.release();
  }
});
