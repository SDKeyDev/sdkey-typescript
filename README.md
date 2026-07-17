# @sdkey/sdk

Official TypeScript client for [SDKey](https://docs.sdkey.dev) license authentication.

Implements the sealed session protocol: Ed25519-verified handshake, HKDF session keys, and AES-256-GCM validate envelopes. See [PROTOCOL.md](./PROTOCOL.md).

## Install

```bash
npm install @sdkey/sdk
# or
pnpm add @sdkey/sdk
```

Requires Node.js 20+ (Web Crypto / Ed25519) or a modern browser / Cloudflare Worker runtime.

## Quick start

Embed these values from the SDKey dashboard when you ship your app:

```ts
import { SdkeyClient, SdkeyError } from '@sdkey/sdk'

const client = new SdkeyClient({
  apiBaseUrl: 'https://api.sdkey.dev',
  appId: 'YOUR_APP_ID',
  appPublicKeyB64: 'YOUR_APP_PUBLIC_KEY_BASE64',
})

try {
  const result = await client.validate('SDKY-XXXX-XXXX-XXXX-XXXX', 'machine-hwid')
  if (result.success) {
    console.log('licensed', result.status, result.expiresAt)
  } else {
    console.error('denied', result.code, result.message)
  }
} catch (err) {
  if (err instanceof SdkeyError) {
    console.error(err.code, err.message)
  }
  throw err
}
```

`validate` calls `init()` automatically when no session exists. Sessions last ~15 minutes server-side; on `SESSION_EXPIRED` the client clears local state so the next call re-handshakes.

## API

### `new SdkeyClient(options)`

| Option | Type | Description |
|---|---|---|
| `apiBaseUrl` | `string` | API origin (no trailing slash) |
| `appId` | `string` | Application UUID |
| `appPublicKeyB64` | `string` | Raw Ed25519 public key (32 bytes), base64 |
| `fetch` | `typeof fetch` | Optional fetch override (tests / custom agents) |

### Methods

- `init()` — challenge handshake; verifies the signed hello; derives the AES session key
- `validate(licenseKey, hwid)` — sealed validate; **always** decrypts then verifies the Ed25519 signature before trusting `success`
- `getSession()` / `clearSession()` — inspect or drop the local session

### Errors

Protocol / transport failures throw `SdkeyError` with a `code`:

`INIT_FAILED` · `HELLO_SIGNATURE_INVALID` · `VALIDATE_RESPONSE_INVALID` · `RESPONSE_SIGNATURE_INVALID` · `SESSION_MISMATCH` · `CLOCK_SKEW` · `NETWORK`

License denials (banned, HWID mismatch, etc.) return a normal `ValidateResult` with `success: false` — they are not thrown.

## Security notes

- Never ship app **private** keys in a client.
- Do not skip signature verification — that is the anti-spoof binding.
- This package is open source; the SDKey server remains a separate product.

## Development

```bash
pnpm install
pnpm test
pnpm build
```

## License

MIT
