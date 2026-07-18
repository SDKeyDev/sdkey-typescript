import {
  CLIENT_NONCE_BYTES,
  CLOCK_SKEW_SECONDS,
  PROTOCOL_VERSION,
  VALIDATE_NONCE_BYTES,
} from './crypto/constants.js'
import { base64ToBytes, bytesToBase64 } from './crypto/encoding.js'
import {
  deriveSessionAesKey,
  importPublicKey,
  openAesGcm,
  sealAesGcm,
  verifySignature,
} from './crypto/seal.js'
import { SdkeyError } from './errors.js'
import type { SdkeyClientOptions, SessionState, ValidateResult } from './types.js'

type SessionInitResponse = {
  success?: boolean
  sessionId?: string
  serverNonceB64?: string
  hkdfSaltB64?: string
  timestamp?: number
  signatureB64?: string
  v?: number
  error?: string
  code?: string
}

type ValidateEnvelope = {
  sessionId?: string
  ivB64?: string
  ciphertextB64?: string
  tagB64?: string
  signatureB64?: string
  success?: boolean
  error?: string
  code?: string
}

/**
 * SDKey license client.
 *
 * Flow: `init()` (session handshake) → `validate(licenseKey, hwid?)` (sealed request).
 * `validate` calls `init` automatically when no session exists.
 */
export class SdkeyClient {
  private readonly opts: SdkeyClientOptions
  private readonly fetchImpl: typeof fetch
  private publicKey: CryptoKey | null = null
  private session: SessionState | null = null

  constructor(opts: SdkeyClientOptions) {
    if (!opts.appVersion) {
      throw new SdkeyError('UNKNOWN', 'appVersion is required')
    }
    this.opts = {
      ...opts,
      apiBaseUrl: opts.apiBaseUrl.replace(/\/+$/, ''),
    }
    this.fetchImpl = opts.fetch ?? globalThis.fetch.bind(globalThis)
  }

  /** Active crypto session, if any. */
  getSession(): SessionState | null {
    return this.session
  }

  /** Drop the current crypto session (next `validate` will re-init). */
  clearSession(): void {
    this.session = null
  }

  async init(): Promise<SessionState> {
    this.publicKey = await importPublicKey(this.opts.appPublicKeyB64)
    const clientNonce = crypto.getRandomValues(new Uint8Array(CLIENT_NONCE_BYTES))

    let res: Response
    try {
      res = await this.fetchImpl(`${this.opts.apiBaseUrl}/api/v1/session/init`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          appId: this.opts.appId,
          clientNonceB64: bytesToBase64(clientNonce),
          clientVersion: this.opts.appVersion,
        }),
      })
    } catch (cause) {
      throw new SdkeyError('NETWORK', 'session init request failed', cause)
    }

    const body = (await res.json()) as SessionInitResponse
    if (!res.ok || !body.success) {
      throw new SdkeyError(
        'INIT_FAILED',
        body.error ?? 'session init failed',
        undefined,
        body.code,
      )
    }

    if (
      !body.sessionId ||
      !body.serverNonceB64 ||
      !body.hkdfSaltB64 ||
      body.timestamp === undefined ||
      !body.signatureB64
    ) {
      throw new SdkeyError('INIT_FAILED', 'session init response incomplete')
    }

    const hello = {
      appId: this.opts.appId,
      hkdfSaltB64: body.hkdfSaltB64,
      serverNonceB64: body.serverNonceB64,
      sessionId: body.sessionId,
      timestamp: body.timestamp,
      v: PROTOCOL_VERSION,
    }

    const ok = await verifySignature(this.publicKey, hello, body.signatureB64)
    if (!ok) {
      throw new SdkeyError('HELLO_SIGNATURE_INVALID', 'hello signature verification failed')
    }

    const aesKey = await deriveSessionAesKey({
      clientNonce,
      serverNonce: base64ToBytes(body.serverNonceB64),
      saltB64: body.hkdfSaltB64,
      appId: this.opts.appId,
    })

    this.session = {
      sessionId: body.sessionId,
      aesKey,
      serverNonceB64: body.serverNonceB64,
      hkdfSaltB64: body.hkdfSaltB64,
    }
    return this.session
  }

  /**
   * Sealed license validate. Omit `hwid` for web clients (JSON key is not sent).
   */
  async validate(licenseKey: string, hwid?: string): Promise<ValidateResult> {
    if (!this.session || !this.publicKey) {
      await this.init()
    }
    const session = this.session!
    const publicKey = this.publicKey!

    const inner: {
      hwid?: string
      licenseKey: string
      nonce: string
      timestamp: number
      v: number
    } = {
      licenseKey,
      nonce: bytesToBase64(crypto.getRandomValues(new Uint8Array(VALIDATE_NONCE_BYTES))),
      timestamp: Math.floor(Date.now() / 1000),
      v: PROTOCOL_VERSION,
    }
    if (hwid !== undefined) {
      inner.hwid = hwid
    }

    const sealed = await sealAesGcm(session.aesKey, new TextEncoder().encode(JSON.stringify(inner)))

    let res: Response
    try {
      res = await this.fetchImpl(`${this.opts.apiBaseUrl}/api/v1/licenses/validate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionId: session.sessionId,
          ...sealed,
        }),
      })
    } catch (cause) {
      throw new SdkeyError('NETWORK', 'validate request failed', cause)
    }

    const envelope = (await res.json()) as ValidateEnvelope

    if (!envelope.ivB64 || !envelope.ciphertextB64 || !envelope.tagB64 || !envelope.signatureB64) {
      if (envelope.code === 'SESSION_EXPIRED') {
        this.clearSession()
      }
      throw new SdkeyError(
        'VALIDATE_RESPONSE_INVALID',
        envelope.error ?? 'invalid validate response',
        undefined,
        envelope.code,
      )
    }

    const plainBytes = await openAesGcm(session.aesKey, {
      ivB64: envelope.ivB64,
      ciphertextB64: envelope.ciphertextB64,
      tagB64: envelope.tagB64,
    })
    const plaintext = JSON.parse(new TextDecoder().decode(plainBytes)) as ValidateResult & {
      sessionId: string
      v: number
      subscriptionTier?: number
    }

    // Mandatory order: decrypt → verify → skew/session → then trust success.
    const verified = await verifySignature(publicKey, plaintext, envelope.signatureB64)
    if (!verified) {
      throw new SdkeyError('RESPONSE_SIGNATURE_INVALID', 'response signature verification failed')
    }

    if (plaintext.sessionId !== session.sessionId) {
      throw new SdkeyError('SESSION_MISMATCH', 'sessionId mismatch')
    }
    if (Math.abs(Math.floor(Date.now() / 1000) - plaintext.timestamp) > CLOCK_SKEW_SECONDS) {
      throw new SdkeyError('CLOCK_SKEW', 'response clock skew')
    }

    if (plaintext.code === 'SESSION_EXPIRED') {
      this.clearSession()
    }

    return {
      success: plaintext.success,
      code: plaintext.code,
      message: plaintext.message,
      status: plaintext.status ?? null,
      expiresAt: plaintext.expiresAt ?? null,
      subscriptionTier:
        typeof plaintext.subscriptionTier === 'number' ? plaintext.subscriptionTier : null,
      timestamp: plaintext.timestamp,
    }
  }
}
