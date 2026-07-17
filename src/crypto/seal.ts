import {
  AES_GCM_IV_BYTES,
  AES_GCM_TAG_BYTES,
  SESSION_AES_KEY_BYTES,
  SESSION_HKDF_INFO_PREFIX,
} from './constants.js'
import { canonicalJson } from './canonical-json.js'
import { asBufferSource, base64ToBytes, bytesToBase64 } from './encoding.js'

export async function importPublicKey(publicKeyB64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    asBufferSource(base64ToBytes(publicKeyB64)),
    { name: 'Ed25519' },
    false,
    ['verify'],
  )
}

export async function verifySignature(
  publicKey: CryptoKey,
  payload: unknown,
  signatureB64: string,
): Promise<boolean> {
  return crypto.subtle.verify(
    'Ed25519',
    publicKey,
    asBufferSource(base64ToBytes(signatureB64)),
    asBufferSource(canonicalJson(payload)),
  )
}

export async function deriveSessionAesKey(params: {
  clientNonce: Uint8Array
  serverNonce: Uint8Array
  saltB64: string
  appId: string
}): Promise<Uint8Array> {
  const ikm = new Uint8Array(params.clientNonce.length + params.serverNonce.length)
  ikm.set(params.clientNonce, 0)
  ikm.set(params.serverNonce, params.clientNonce.length)
  const salt = base64ToBytes(params.saltB64)
  const info = new TextEncoder().encode(`${SESSION_HKDF_INFO_PREFIX}${params.appId}`)
  const baseKey = await crypto.subtle.importKey('raw', asBufferSource(ikm), 'HKDF', false, [
    'deriveBits',
  ])
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: asBufferSource(salt), info },
    baseKey,
    SESSION_AES_KEY_BYTES * 8,
  )
  return new Uint8Array(bits)
}

export type SealedEnvelope = {
  ivB64: string
  ciphertextB64: string
  tagB64: string
}

export async function sealAesGcm(aesKey: Uint8Array, plaintext: Uint8Array): Promise<SealedEnvelope> {
  const key = await crypto.subtle.importKey(
    'raw',
    asBufferSource(aesKey),
    { name: 'AES-GCM' },
    false,
    ['encrypt'],
  )
  const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES))
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      key,
      asBufferSource(plaintext),
    ),
  )
  return {
    ivB64: bytesToBase64(iv),
    ciphertextB64: bytesToBase64(encrypted.slice(0, encrypted.length - AES_GCM_TAG_BYTES)),
    tagB64: bytesToBase64(encrypted.slice(encrypted.length - AES_GCM_TAG_BYTES)),
  }
}

export async function openAesGcm(aesKey: Uint8Array, envelope: SealedEnvelope): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    asBufferSource(aesKey),
    { name: 'AES-GCM' },
    false,
    ['decrypt'],
  )
  const iv = base64ToBytes(envelope.ivB64)
  const ciphertext = base64ToBytes(envelope.ciphertextB64)
  const tag = base64ToBytes(envelope.tagB64)
  const combined = new Uint8Array(ciphertext.length + tag.length)
  combined.set(ciphertext, 0)
  combined.set(tag, ciphertext.length)
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: asBufferSource(iv), tagLength: 128 },
      key,
      asBufferSource(combined),
    ),
  )
}
