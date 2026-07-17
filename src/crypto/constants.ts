/** Wire-protocol constants (protocol v1). */

export const PROTOCOL_VERSION = 1

export const CLOCK_SKEW_SECONDS = 60

export const CLIENT_NONCE_BYTES = 32
export const SERVER_NONCE_BYTES = 32
export const VALIDATE_NONCE_BYTES = 16

export const AES_GCM_IV_BYTES = 12
export const AES_GCM_TAG_BITS = 128
export const AES_GCM_TAG_BYTES = 16
export const SESSION_AES_KEY_BYTES = 32

export const SESSION_HKDF_INFO_PREFIX = 'sdkey-session-v1'

/** Failure codes that may appear in a sealed validate response. */
export const VALIDATE_FAILURE_CODES = [
  'SESSION_EXPIRED',
  'CLOCK_SKEW',
  'REPLAY',
  'LICENSE_NOT_FOUND',
  'APP_MISMATCH',
  'BANNED',
  'EXPIRED',
  'HWID_MISMATCH',
  'DECRYPT_FAIL',
  'APP_DISABLED',
] as const

export type ValidateFailureCode = (typeof VALIDATE_FAILURE_CODES)[number]
