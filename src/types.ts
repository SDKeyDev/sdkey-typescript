export type SdkeyClientOptions = {
  /** API origin, e.g. `https://api.sdkey.dev` (no trailing slash). */
  apiBaseUrl: string
  /** Application UUID from the SDKey dashboard. */
  appId: string
  /**
   * Exact application version string. Sent as `clientVersion` on session init
   * and client-auth calls; must match `applications.version` or the server
   * returns `APP_OUTDATED`.
   */
  appVersion: string
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
  /** User-facing text from the sealed body (`message`, not `error`). */
  message: string
  status: string | null
  expiresAt: string | null
  /** Present on success (≥ 0); `null` on sealed failure. */
  subscriptionTier: number | null
  timestamp: number
}

export type ClientAuthUser = {
  id: string
  username: string
  email: string | null
  applicationId: string
}

export type ClientAuthLicense = {
  id: string
  status: string
  expiresAt: string | null
  subscriptionTier: number
}

export type ClientAuthSession = {
  ip: string
  hwid: string | null
}

/** Success shape for register / login / upgrade (plaintext JSON). */
export type ClientAuthResult = {
  success: true
  sessionToken: string
  expiresAt: string
  user: ClientAuthUser
  license: ClientAuthLicense | null
  session: ClientAuthSession
}

export type RegisterParams = {
  username: string
  password: string
  email?: string
  licenseKey?: string
  hwid?: string
}

export type LoginParams = {
  username: string
  password: string
  hwid?: string
}

export type UpgradeParams = {
  username: string
  licenseKey: string
  hwid?: string
}
