/**
 * Deterministic JSON encoding for Ed25519 signing.
 * Object keys sorted lexicographically, no insignificant whitespace.
 */
export function canonicalJson(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalize(value))
}

export function canonicalize(value: unknown): string {
  if (value === null) return 'null'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('canonicalJson: non-finite numbers are not allowed')
    }
    return JSON.stringify(value)
  }
  if (typeof value === 'string') return JSON.stringify(value)
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalize(item)).join(',')}]`
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>
    const keys = Object.keys(obj)
      .filter((k) => obj[k] !== undefined)
      .sort()
    const body = keys.map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`).join(',')
    return `{${body}}`
  }
  throw new Error(`canonicalJson: unsupported type ${typeof value}`)
}
