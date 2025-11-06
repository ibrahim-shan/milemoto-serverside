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

function isDuplicateEntry(error: unknown): error is { code: string } {
  return Boolean(
    error &&
      typeof error === 'object' &&
      'code' in error &&
      (error as { code?: string }).code === 'ER_DUP_ENTRY'
  );
}

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
    if (isDuplicateEntry(e)) {
      return res.status(409).json({
        code: 'DuplicateCountry',
        message: 'Country code already exists.',
      });
    }
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

    const conn = await pool.getConnection();
    let inTransaction = false;
    try {
      await conn.beginTransaction();
      inTransaction = true;

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

      const [result] = await conn.query<ResultSetHeader>(
        `UPDATE countries SET ${fields.join(', ')} WHERE id = ?`,
        values
      );

      if (result.affectedRows === 0) {
        await conn.rollback();
        return res.status(404).json({ code: 'NotFound', message: 'Country not found' });
      }

      if (body.status === 'inactive') {
        await conn.query(`UPDATE states SET status_effective = 'inactive' WHERE country_id = ?`, [
          countryId,
        ]);
        await conn.query(
          `UPDATE cities c
             JOIN states s ON c.state_id = s.id
           SET c.status_effective = 'inactive'
         WHERE s.country_id = ?`,
          [countryId]
        );
      } else if (body.status === 'active') {
        await conn.query(
          `UPDATE states
              SET status_effective = CASE WHEN status = 'active' THEN 'active' ELSE 'inactive' END
            WHERE country_id = ?`,
          [countryId]
        );
        await conn.query(
          `UPDATE cities c
             JOIN states s ON c.state_id = s.id
           SET c.status_effective =
             CASE
               WHEN c.status = 'active' AND s.status_effective = 'active' THEN 'active'
               ELSE 'inactive'
             END
         WHERE s.country_id = ?`,
          [countryId]
        );
      }

      const [rows] = await conn.query<RowDataPacket[]>('SELECT * FROM countries WHERE id = ?', [
        countryId,
      ]);

      await conn.commit();
      return res.json(rows[0]);
    } catch (e) {
      if (inTransaction) {
        try {
          await conn.rollback();
        } catch {}
      }
      if (isDuplicateEntry(e)) {
        return res.status(409).json({
          code: 'DuplicateCountry',
          message: 'Country code already exists.',
        });
      }
      return next(e);
    } finally {
      conn.release();
    }
  } catch (e) {
    if (isDuplicateEntry(e)) {
      return res.status(409).json({
        code: 'DuplicateCountry',
        message: 'Country code already exists.',
      });
    }
    return next(e);
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
    const includeInactive =
      ['1', 'true', 'yes'].includes(String(req.query.includeInactive ?? '').toLowerCase()) || false;
    const sql = includeInactive
      ? 'SELECT id, name, status FROM countries ORDER BY name ASC'
      : "SELECT id, name, status FROM countries WHERE status = 'active' ORDER BY name ASC";
    const [items] = await pool.query<RowDataPacket[]>(sql);
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

    const [countryRows] = await pool.query<RowDataPacket[]>(
      'SELECT name, status FROM countries WHERE id = ? LIMIT 1',
      [country_id]
    );
    const country = countryRows[0];
    if (!country)
      return res.status(404).json({ code: 'ParentNotFound', message: 'Country not found' });
    if (status === 'active' && country.status !== 'active') {
      return res.status(400).json({
        code: 'ParentInactive',
        message: 'Cannot activate state because the parent country is inactive.',
      });
    }

    const statusEffective =
      status === 'active' && country.status === 'active' ? 'active' : 'inactive';

    const [result] = await pool.query<ResultSetHeader>(
      'INSERT INTO states (name, country_id, status, status_effective) VALUES (?, ?, ?, ?)',
      [name, country_id, status, statusEffective]
    );

    res.status(201).json({
      id: result.insertId,
      name,
      country_id,
      status,
      status_effective: statusEffective,
      country_name: country.name,
      country_status: country.status,
      country_status_effective: country.status,
    });
  } catch (e) {
    if (isDuplicateEntry(e)) {
      return res.status(409).json({
        code: 'DuplicateState',
        message: 'State name already exists for this country.',
      });
    }
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
         s.id,
         s.name,
         s.status,
         s.status_effective,
         s.created_at,
         s.updated_at,
         c.id AS country_id,
         c.name AS country_name,
         c.status AS country_status,
         c.status AS country_status_effective
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

    const [existingRows] = await pool.query<RowDataPacket[]>(
      `SELECT id, country_id, status FROM states WHERE id = ? LIMIT 1`,
      [stateId]
    );
    const existing = existingRows[0];
    if (!existing) {
      return res.status(404).json({ code: 'NotFound', message: 'State not found' });
    }

    const targetCountryId = body.country_id ?? Number(existing.country_id);
    const targetStatus = body.status ?? existing.status;

    const [countryRows] = await pool.query<RowDataPacket[]>(
      `SELECT id, name, status FROM countries WHERE id = ? LIMIT 1`,
      [targetCountryId]
    );
    const country = countryRows[0];
    if (!country) {
      return res.status(404).json({ code: 'ParentNotFound', message: 'Country not found' });
    }

    if (targetStatus === 'active' && country.status !== 'active') {
      return res.status(400).json({
        code: 'ParentInactive',
        message: 'Cannot activate state because the parent country is inactive.',
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
    const stateEffective =
      targetStatus === 'active' && country.status === 'active' ? 'active' : 'inactive';
    fields.push('status_effective = ?');
    values.push(stateEffective);
    values.push(stateId);

    const [result] = await pool.query<ResultSetHeader>(
      `UPDATE states SET ${fields.join(', ')} WHERE id = ?`,
      values
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ code: 'NotFound', message: 'State not found' });
    }

    if (stateEffective === 'inactive') {
      await pool.query(`UPDATE cities SET status_effective = 'inactive' WHERE state_id = ?`, [
        stateId,
      ]);
    } else {
      await pool.query(
        `UPDATE cities
            SET status_effective = CASE WHEN status = 'active' THEN 'active' ELSE 'inactive' END
          WHERE state_id = ?`,
        [stateId]
      );
    }

    // Return the updated record
    const [rows] = await pool.query<RowDataPacket[]>(
      `SELECT
         s.id,
         s.name,
         s.status,
         s.status_effective,
         s.country_id,
         c.name AS country_name,
         c.status AS country_status,
         c.status AS country_status_effective
       FROM states s
       JOIN countries c ON c.id = s.country_id
      WHERE s.id = ?`,
      [stateId]
    );
    res.json(rows[0]);
  } catch (e) {
    if (isDuplicateEntry(e)) {
      return res.status(409).json({
        code: 'DuplicateState',
        message: 'State name already exists for this country.',
      });
    }
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
      "SELECT id, name, status, status_effective FROM states WHERE status_effective = 'active' ORDER BY name ASC"
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

    const [stateRows] = await pool.query<RowDataPacket[]>(
      `SELECT
         s.id,
         s.name,
         s.status,
         s.status_effective,
         c.id AS country_id,
         c.name AS country_name,
         c.status AS country_status
         FROM states s
         JOIN countries c ON c.id = s.country_id
        WHERE s.id = ? LIMIT 1`,
      [state_id]
    );
    const parentState = stateRows[0];
    if (!parentState)
      return res.status(404).json({ code: 'ParentNotFound', message: 'State not found' });
    if (
      status === 'active' &&
      (parentState.status !== 'active' || parentState.country_status !== 'active')
    ) {
      return res.status(400).json({
        code: 'ParentInactive',
        message: 'Cannot activate city because the parent state or country is inactive.',
      });
    }

    const parentStateEffective =
      parentState.status_effective ??
      (parentState.status === 'active' && parentState.country_status === 'active'
        ? 'active'
        : 'inactive');
    const statusEffective =
      status === 'active' && parentStateEffective === 'active' ? 'active' : 'inactive';

    const [result] = await pool.query<ResultSetHeader>(
      'INSERT INTO cities (name, state_id, status, status_effective) VALUES (?, ?, ?, ?)',
      [name, state_id, status, statusEffective]
    );

    res.status(201).json({
      id: result.insertId,
      name,
      state_id,
      status,
      status_effective: statusEffective,
      state_name: parentState.name,
      state_status: parentState.status,
      state_status_effective: parentStateEffective,
      country_id: parentState.country_id,
      country_name: parentState.country_name,
      country_status: parentState.country_status,
      country_status_effective: parentState.country_status,
    });
  } catch (e) {
    if (isDuplicateEntry(e)) {
      return res.status(409).json({
        code: 'DuplicateCity',
        message: 'City name already exists for this state.',
      });
    }
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
         ci.id,
         ci.name,
         ci.status,
         ci.status_effective,
         ci.created_at,
         s.id AS state_id,
         s.name AS state_name,
         s.status AS state_status,
         s.status_effective AS state_status_effective,
         co.id AS country_id,
         co.name AS country_name,
         co.status AS country_status,
         co.status AS country_status_effective
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

    const [existingRows] = await pool.query<RowDataPacket[]>(
      `SELECT id, state_id, status FROM cities WHERE id = ? LIMIT 1`,
      [cityId]
    );
    const existing = existingRows[0];
    if (!existing) return res.status(404).json({ code: 'NotFound', message: 'City not found' });

    const targetStateId = body.state_id ?? Number(existing.state_id);
    const targetStatus = body.status ?? existing.status;

    const [stateRows] = await pool.query<RowDataPacket[]>(
      `SELECT
         s.id,
         s.name,
         s.status,
         s.status_effective,
         c.id AS country_id,
         c.name AS country_name,
         c.status AS country_status
         FROM states s
         JOIN countries c ON c.id = s.country_id
        WHERE s.id = ? LIMIT 1`,
      [targetStateId]
    );
    const parentState = stateRows[0];
    if (!parentState)
      return res.status(404).json({ code: 'ParentNotFound', message: 'State not found' });
    if (
      targetStatus === 'active' &&
      (parentState.status !== 'active' || parentState.country_status !== 'active')
    ) {
      return res.status(400).json({
        code: 'ParentInactive',
        message: 'Cannot activate city because the parent state or country is inactive.',
      });
    }

    const parentStateEffective =
      parentState.status_effective ??
      (parentState.status === 'active' && parentState.country_status === 'active'
        ? 'active'
        : 'inactive');
    const cityEffective =
      targetStatus === 'active' && parentStateEffective === 'active' ? 'active' : 'inactive';

    const fields: string[] = [];
    const values: (string | number)[] = [];
    for (const [key, value] of Object.entries(body)) {
      if (value !== undefined) {
        fields.push(`${key} = ?`);
        values.push(value);
      }
    }
    fields.push('status_effective = ?');
    values.push(cityEffective);
    values.push(cityId);

    const [result] = await pool.query<ResultSetHeader>(
      `UPDATE cities SET ${fields.join(', ')} WHERE id = ?`,
      values
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ code: 'NotFound', message: 'City not found' });
    }

    // Return the updated record
    const [rows] = await pool.query<RowDataPacket[]>(
      `SELECT
         ci.id,
         ci.name,
         ci.status,
         ci.status_effective,
         ci.state_id,
         s.name AS state_name,
         s.status AS state_status,
         s.status_effective AS state_status_effective,
         co.id AS country_id,
         co.name AS country_name,
         co.status AS country_status,
         co.status AS country_status_effective
       FROM cities ci
       JOIN states s ON s.id = ci.state_id
       JOIN countries co ON co.id = s.country_id
      WHERE ci.id = ?`,
      [cityId]
    );
    res.json(rows[0]);
  } catch (e) {
    if (isDuplicateEntry(e)) {
      return res.status(409).json({
        code: 'DuplicateCity',
        message: 'City name already exists for this state.',
      });
    }
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
    if (isDuplicateEntry(e)) {
      return res.status(409).json({
        code: 'DuplicateCountry',
        message: 'Country code already exists.',
      });
    }
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
        const err = new Error(`Invalid country_code: ${row.country_code}`);
        Object.assign(err, { status: 400, code: 'InvalidReference' });
        throw err;
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
    if (isDuplicateEntry(e)) {
      return res.status(409).json({
        code: 'DuplicateState',
        message: 'State name already exists for this country.',
      });
    }
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
        const err = new Error(
          `Invalid combo: state=${row.state_name}, country=${row.country_code}`
        );
        Object.assign(err, { status: 400, code: 'InvalidReference' });
        throw err;
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
    if (isDuplicateEntry(e)) {
      return res.status(409).json({
        code: 'DuplicateCity',
        message: 'City name already exists for this state.',
      });
    }
    next(e);
  } finally {
    conn.release();
  }
});
