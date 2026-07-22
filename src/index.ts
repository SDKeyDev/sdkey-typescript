export { SdkeyClient } from './client.js'
export { SdkeyError, type SdkeyErrorCode } from './errors.js'
export { getHardwareId } from './hwid.js'
export type {
  ClientAuthLicense,
  ClientAuthResult,
  ClientAuthSession,
  ClientAuthUser,
  LoginParams,
  RegisterParams,
  SdkeyClientOptions,
  SessionState,
  UpgradeParams,
  ValidateResult,
} from './types.js'
export {
  PROTOCOL_VERSION,
  CLOCK_SKEW_SECONDS,
  CLIENT_NONCE_BYTES,
  SERVER_NONCE_BYTES,
  VALIDATE_NONCE_BYTES,
  AES_GCM_IV_BYTES,
  SESSION_AES_KEY_BYTES,
  SESSION_HKDF_INFO_PREFIX,
  VALIDATE_FAILURE_CODES,
  type ValidateFailureCode,
} from './crypto/constants.js'
export { canonicalJson, canonicalize } from './crypto/canonical-json.js'
export { bytesToBase64, base64ToBytes } from './crypto/encoding.js'
export {
  importPublicKey,
  verifySignature,
  deriveSessionAesKey,
  sealAesGcm,
  openAesGcm,
  type SealedEnvelope,
} from './crypto/seal.js'
