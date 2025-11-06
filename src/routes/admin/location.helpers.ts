import { z } from 'zod';

// Shared status enum
const StatusEnum = z.enum(['active', 'inactive']);

// Shared pagination schema
export const ListQuery = z.object({
  search: z.string().optional().default(''),
  page: z.coerce.number().int().min(1).optional().default(1),
  limit: z.coerce.number().int().min(1).max(100).optional().default(10),
});

// ==== COUNTRIES ====

export const CreateCountry = z.object({
  name: z.string().min(2, 'Name is required'),
  code: z.string().min(2, 'Code is required').max(10),
  status: StatusEnum,
});
export type CreateCountryDto = z.infer<typeof CreateCountry>;

export const UpdateCountry = z.object({
  name: z.string().min(2, 'Name is required').optional(),
  code: z.string().min(2, 'Code is required').max(10).optional(),
  status: StatusEnum.optional(),
});
export type UpdateCountryDto = z.infer<typeof UpdateCountry>;

// ==== STATES ====

export const CreateState = z.object({
  name: z.string().min(2, 'Name is required'),
  // We use coerce.number() to safely convert string inputs (from forms/JSON) to numbers
  country_id: z.coerce.number().int().min(1, 'Country is required'),
  status: StatusEnum,
});
export type CreateStateDto = z.infer<typeof CreateState>;

export const UpdateState = z.object({
  name: z.string().min(2, 'Name is required').optional(),
  country_id: z.coerce.number().int().min(1, 'Country is required').optional(),
  status: StatusEnum.optional(),
});
export type UpdateStateDto = z.infer<typeof UpdateState>;

// ==== CITIES ====

export const CreateCity = z.object({
  name: z.string().min(2, 'Name is required'),
  state_id: z.coerce.number().int().min(1, 'State is required'),
  status: StatusEnum,
});
export type CreateCityDto = z.infer<typeof CreateCity>;

export const UpdateCity = z.object({
  name: z.string().min(2, 'Name is required').optional(),
  state_id: z.coerce.number().int().min(1, 'State is required').optional(),
  status: StatusEnum.optional(),
});
export type UpdateCityDto = z.infer<typeof UpdateCity>;

// ==== IMPORT ====

export const ImportCountries = z.array(CreateCountry);
export const ImportStates = z.array(CreateState);
export const ImportCities = z.array(CreateCity);
