import { describe, expect, it, vi } from 'vitest'
import { SdkeyClient } from '../src/client.js'
import { SdkeyError } from '../src/errors.js'
import { canonicalJson } from '../src/crypto/canonical-json.js'
import { asBufferSource, base64ToBytes, bytesToBase64 } from '../src/crypto/encoding.js'
import { deriveSessionAesKey, sealAesGcm } from '../src/crypto/seal.js'
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

describe('SdkeyClient', () => {
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
        expect(capturedClientNonce).not.toBeNull()
        const aesKey = await deriveSessionAesKey({
          clientNonce: capturedClientNonce!,
          serverNonce,
          saltB64: bytesToBase64(hkdfSalt),
          appId,
        })
        const plaintext = {
          success: true,
          code: 'OK',
          message: 'valid',
          status: 'active',
          expiresAt: null,
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

    const client = new SdkeyClient({
      apiBaseUrl: 'https://api.example.test',
      appId,
      appPublicKeyB64: publicKeyB64,
      fetch: fetchMock as unknown as typeof fetch,
    })

    const result = await client.validate('SDKY-TEST-TEST-TEST-TEST', 'hwid-1')
    expect(result.success).toBe(true)
    expect(result.code).toBe('OK')
    expect(client.getSession()?.sessionId).toBe(sessionId)
    expect(fetchMock).toHaveBeenCalledTimes(2)
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

    const client = new SdkeyClient({
      apiBaseUrl: 'https://api.example.test',
      appId: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
      appPublicKeyB64: publicKeyB64,
      fetch: fetchMock as unknown as typeof fetch,
    })

    await expect(client.init()).rejects.toMatchObject({
      name: 'SdkeyError',
      code: 'HELLO_SIGNATURE_INVALID',
    } satisfies Partial<SdkeyError>)
  })
})
