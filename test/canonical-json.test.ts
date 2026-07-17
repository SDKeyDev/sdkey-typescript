import { describe, expect, it } from 'vitest'
import { canonicalize, canonicalJson } from '../src/crypto/canonical-json.js'

describe('canonicalJson', () => {
  it('sorts object keys lexicographically', () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}')
  })

  it('omits undefined fields', () => {
    expect(canonicalize({ a: 1, b: undefined })).toBe('{"a":1}')
  })

  it('encodes nested structures without whitespace', () => {
    expect(canonicalize({ z: [true, null, 'x'], m: { k: 0 } })).toBe(
      '{"m":{"k":0},"z":[true,null,"x"]}',
    )
  })

  it('returns UTF-8 bytes', () => {
    const bytes = canonicalJson({ a: 1 })
    expect(new TextDecoder().decode(bytes)).toBe('{"a":1}')
  })
})
