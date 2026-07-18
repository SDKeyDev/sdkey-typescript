import { describe, expect, it, vi } from 'vitest'
import { SdkeyClient } from '../src/client.js'
import { SdkeyError } from '../src/errors.js'
import { canonicalJson } from '../src/crypto/canonical-json.js'
import { asBufferSource, base64ToBytes, bytesToBase64 } from '../src/crypto/encoding.js'
import { deriveSessionAesKey, openAesGcm, sealAesGcm } from '../src/crypto/seal.js'
import { PROTOCOL_VERSION } from '../src/crypto/constants.js'

async function generateEd25519Pair() {
  const pair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])
  const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))
  return { ...pair, publicKeyB64: bytesToBase64(rawPub) }
}

async function signPayload(privateKey: CryptoKey, payload: unknown): Promise<string> {
  const sig = new Uint8Array(
    await crypto.subtle.sign('Ed25519', privateKey, asBufferSource(canonicalJson(payload))),
  )
  return bytesToBase64(sig)
}

function baseClientOpts(overrides: {
  publicKeyB64: string
  fetch: typeof fetch
  appId?: string
  appVersion?: string
}) {
  return {
    apiBaseUrl: 'https://api.example.test',
    appId: overrides.appId ?? 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
    appVersion: overrides.appVersion ?? '1.0.0',
    appPublicKeyB64: overrides.publicKeyB64,
    fetch: overrides.fetch,
  }
}

describe('SdkeyClient', () => {
  it('requires appVersion', () => {
    expect(
      () =>
        new SdkeyClient({
          apiBaseUrl: 'https://api.example.test',
          appId: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
          appVersion: '',
          appPublicKeyB64: 'x',
        }),
    ).toThrowError(SdkeyError)
  })

  it('inits a session and validates a sealed license response', async () => {
    const { privateKey, publicKeyB64 } = await generateEd25519Pair()
    const appId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    const sessionId = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
    const serverNonce = crypto.getRandomValues(new Uint8Array(32))
    const hkdfSalt = crypto.getRandomValues(new Uint8Array(16))
    const timestamp = Math.floor(Date.now() / 1000)

    let capturedClientNonce: Uint8Array | null = null

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.endsWith('/api/v1/session/init')) {
        const req = JSON.parse(String(init?.body)) as {
          clientNonceB64: string
          clientVersion: string
        }
        expect(req.clientVersion).toBe('1.2.3')
        capturedClientNonce = base64ToBytes(req.clientNonceB64)
        const hello = {
          appId,
          hkdfSaltB64: bytesToBase64(hkdfSalt),
          serverNonceB64: bytesToBase64(serverNonce),
          sessionId,
          timestamp,
          v: PROTOCOL_VERSION,
        }
        return new Response(
          JSON.stringify({
            success: true,
            ...hello,
            signatureB64: await signPayload(privateKey, hello),
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        )
      }

      if (url.endsWith('/api/v1/licenses/validate')) {
        expect(capturedClientNonce).not.toBeNull()
        const aesKey = await deriveSessionAesKey({
          clientNonce: capturedClientNonce!,
          serverNonce,
          saltB64: bytesToBase64(hkdfSalt),
          appId,
        })
        const outer = JSON.parse(String(init?.body)) as {
          ivB64: string
          ciphertextB64: string
          tagB64: string
        }
        const innerBytes = await openAesGcm(aesKey, outer)
        const inner = JSON.parse(new TextDecoder().decode(innerBytes)) as {
          hwid?: string
          licenseKey: string
        }
        expect(inner.hwid).toBe('hwid-1')
        expect(inner.licenseKey).toBe('SDKY-TEST-TEST-TEST-TEST')

        const plaintext = {
          success: true,
          code: 'OK',
          message: 'validated',
          status: 'active',
          expiresAt: null,
          subscriptionTier: 2,
          sessionId,
          timestamp: Math.floor(Date.now() / 1000),
          v: PROTOCOL_VERSION,
        }
        const sealed = await sealAesGcm(aesKey, new TextEncoder().encode(JSON.stringify(plaintext)))
        return new Response(
          JSON.stringify({
            sessionId,
            ...sealed,
            signatureB64: await signPayload(privateKey, plaintext),
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        )
      }

      return new Response('not found', { status: 404 })
    })

    const client = new SdkeyClient(
      baseClientOpts({
        publicKeyB64,
        fetch: fetchMock as unknown as typeof fetch,
        appVersion: '1.2.3',
      }),
    )

    const result = await client.validate('SDKY-TEST-TEST-TEST-TEST', 'hwid-1')
    expect(result.success).toBe(true)
    expect(result.code).toBe('OK')
    expect(result.message).toBe('validated')
    expect(result.subscriptionTier).toBe(2)
    expect(client.getSession()?.sessionId).toBe(sessionId)
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('omits hwid from sealed validate when not provided', async () => {
    const { privateKey, publicKeyB64 } = await generateEd25519Pair()
    const appId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    const sessionId = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
    const serverNonce = crypto.getRandomValues(new Uint8Array(32))
    const hkdfSalt = crypto.getRandomValues(new Uint8Array(16))
    const timestamp = Math.floor(Date.now() / 1000)
    let capturedClientNonce: Uint8Array | null = null

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.endsWith('/api/v1/session/init')) {
        const req = JSON.parse(String(init?.body)) as { clientNonceB64: string }
        capturedClientNonce = base64ToBytes(req.clientNonceB64)
        const hello = {
          appId,
          hkdfSaltB64: bytesToBase64(hkdfSalt),
          serverNonceB64: bytesToBase64(serverNonce),
          sessionId,
          timestamp,
          v: PROTOCOL_VERSION,
        }
        return new Response(
          JSON.stringify({
            success: true,
            ...hello,
            signatureB64: await signPayload(privateKey, hello),
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        )
      }

      if (url.endsWith('/api/v1/licenses/validate')) {
        const aesKey = await deriveSessionAesKey({
          clientNonce: capturedClientNonce!,
          serverNonce,
          saltB64: bytesToBase64(hkdfSalt),
          appId,
        })
        const outer = JSON.parse(String(init?.body)) as {
          ivB64: string
          ciphertextB64: string
          tagB64: string
        }
        const innerBytes = await openAesGcm(aesKey, outer)
        const inner = JSON.parse(new TextDecoder().decode(innerBytes)) as Record<string, unknown>
        expect(Object.prototype.hasOwnProperty.call(inner, 'hwid')).toBe(false)

        const plaintext = {
          success: true,
          code: 'OK',
          message: 'validated',
          status: 'active',
          expiresAt: null,
          subscriptionTier: 0,
          sessionId,
          timestamp: Math.floor(Date.now() / 1000),
          v: PROTOCOL_VERSION,
        }
        const sealed = await sealAesGcm(aesKey, new TextEncoder().encode(JSON.stringify(plaintext)))
        return new Response(
          JSON.stringify({
            sessionId,
            ...sealed,
            signatureB64: await signPayload(privateKey, plaintext),
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        )
      }

      return new Response('not found', { status: 404 })
    })

    const client = new SdkeyClient(
      baseClientOpts({ publicKeyB64, fetch: fetchMock as unknown as typeof fetch }),
    )
    const result = await client.validate('SDKY-TEST-TEST-TEST-TEST')
    expect(result.success).toBe(true)
    expect(result.subscriptionTier).toBe(0)
  })

  it('surfaces server error and code on init failure', async () => {
    const { publicKeyB64 } = await generateEd25519Pair()
    const fetchMock = vi.fn(async () => {
      return new Response(
        JSON.stringify({
          success: false,
          error: 'Client version outdated',
          code: 'APP_OUTDATED',
        }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      )
    })

    const client = new SdkeyClient(
      baseClientOpts({ publicKeyB64, fetch: fetchMock as unknown as typeof fetch }),
    )

    await expect(client.init()).rejects.toMatchObject({
      name: 'SdkeyError',
      code: 'INIT_FAILED',
      message: 'Client version outdated',
      serverCode: 'APP_OUTDATED',
    } satisfies Partial<SdkeyError>)
  })

  it('throws SdkeyError when hello signature is wrong', async () => {
    const { publicKeyB64 } = await generateEd25519Pair()
    const other = await generateEd25519Pair()

    const fetchMock = vi.fn(async () => {
      const hello = {
        appId: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
        hkdfSaltB64: bytesToBase64(new Uint8Array(16)),
        serverNonceB64: bytesToBase64(new Uint8Array(32)),
        sessionId: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
        timestamp: Math.floor(Date.now() / 1000),
        v: PROTOCOL_VERSION,
      }
      return new Response(
        JSON.stringify({
          success: true,
          ...hello,
          signatureB64: await signPayload(other.privateKey, hello),
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      )
    })

    const client = new SdkeyClient(
      baseClientOpts({ publicKeyB64, fetch: fetchMock as unknown as typeof fetch }),
    )

    await expect(client.init()).rejects.toMatchObject({
      name: 'SdkeyError',
      code: 'HELLO_SIGNATURE_INVALID',
    } satisfies Partial<SdkeyError>)
  })
})
