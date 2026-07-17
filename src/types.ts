export type SdkeyClientOptions = {
  /** API origin, e.g. `https://api.sdkey.dev` (no trailing slash). */
  apiBaseUrl: string
  /** Application UUID from the SDKey dashboard. */
  appId: string
  /** Raw Ed25519 public key (32 bytes), standard or URL-safe base64. */
  appPublicKeyB64: string
  /** Optional fetch implementation (defaults to global `fetch`). */
  fetch?: typeof fetch
}

export type SessionState = {
  sessionId: string
  aesKey: Uint8Array
  serverNonceB64: string
  hkdfSaltB64: string
}

export type ValidateResult = {
  success: boolean
  code: string
  message: string
  status: string | null
  expiresAt: string | null
  timestamp: number
}
