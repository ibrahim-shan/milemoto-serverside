import { env } from './env.js';

// Mutable runtime flags that can be flipped without redeploy via admin endpoints
export const runtimeFlags = {
  // When true, enforce trusted-device fingerprint checks for all users (admins are always enforced)
  trustedDeviceFpEnforceAll: env.TRUSTED_DEVICE_FINGERPRINT_ENABLED,
};
