import { describe, expect, it } from 'vitest'
import { bytesToBase64 } from '../src/crypto/encoding.js'
import { deriveSessionAesKey, openAesGcm, sealAesGcm } from '../src/crypto/seal.js'

describe('AES-GCM seal', () => {
  it('round-trips plaintext', async () => {
    const aesKey = crypto.getRandomValues(new Uint8Array(32))
    const plaintext = new TextEncoder().encode('{"ok":true}')
    const sealed = await sealAesGcm(aesKey, plaintext)
    const opened = await openAesGcm(aesKey, sealed)
    expect(new TextDecoder().decode(opened)).toBe('{"ok":true}')
  })
})

describe('deriveSessionAesKey', () => {
  it('is deterministic for the same inputs', async () => {
    const clientNonce = crypto.getRandomValues(new Uint8Array(32))
    const serverNonce = crypto.getRandomValues(new Uint8Array(32))
    const saltB64 = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)))
    const appId = '11111111-2222-3333-4444-555555555555'

    const a = await deriveSessionAesKey({ clientNonce, serverNonce, saltB64, appId })
    const b = await deriveSessionAesKey({ clientNonce, serverNonce, saltB64, appId })
    expect(bytesToBase64(a)).toBe(bytesToBase64(b))
    expect(a.length).toBe(32)
  })

  it('changes when appId changes', async () => {
    const clientNonce = new Uint8Array(32).fill(1)
    const serverNonce = new Uint8Array(32).fill(2)
    const saltB64 = bytesToBase64(new Uint8Array(16).fill(3))

    const a = await deriveSessionAesKey({
      clientNonce,
      serverNonce,
      saltB64,
      appId: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
    })
    const b = await deriveSessionAesKey({
      clientNonce,
      serverNonce,
      saltB64,
      appId: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
    })
    expect(bytesToBase64(a)).not.toBe(bytesToBase64(b))
  })
})
