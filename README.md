# @sdkey/sdk

Official TypeScript client for [SDKey](https://docs.sdkey.dev) license authentication.

Implements the sealed session protocol: Ed25519-verified handshake, HKDF session keys, and AES-256-GCM validate envelopes, plus plaintext client auth (register / login / upgrade). See [PROTOCOL.md](./PROTOCOL.md).

## Install

```bash
npm install @sdkey/sdk
# or
pnpm add @sdkey/sdk
```

Requires Node.js 20+ (Web Crypto / Ed25519) or a modern browser / Cloudflare Worker runtime.

## Quick start

Embed these values from the SDKey dashboard when you ship your app. `appVersion` must **exactly match** the application's configured version (`APP_OUTDATED` otherwise).

```ts
import { SdkeyClient, SdkeyError } from '@sdkey/sdk'

const client = new SdkeyClient({
  apiBaseUrl: 'https://api.sdkey.dev',
  appId: 'YOUR_APP_ID',
  appVersion: '1.0.0',
  appPublicKeyB64: 'YOUR_APP_PUBLIC_KEY_BASE64',
})

try {
  // hwid is optional (omit for web clients)
  const result = await client.validate('SDKY-XXXX-XXXX-XXXX-XXXX', 'machine-hwid')
  if (result.success) {
    console.log('licensed', result.status, result.expiresAt, result.subscriptionTier)
    console.log('message', result.message) // sealed success text
  } else {
    console.error('denied', result.code, result.message) // sealed failure text
  }
} catch (err) {
  if (err instanceof SdkeyError) {
    // init / transport failures: server text is err.message; server code is err.serverCode
    console.error(err.code, err.message, err.serverCode)
  }
  throw err
}
```

### Hardware ID (Node desktop)

`getHardwareId()` reads a stable OS machine identifier, SHA-256 hashes it, and returns lowercase hex (64 chars). It is **opt-in** — pass the result only when you want HWID binding. Omit `hwid` for browsers / web.

```ts
import { SdkeyClient, getHardwareId } from '@sdkey/sdk'

// Desktop (Node):
await client.validate(key, getHardwareId())

// Web: omit hwid
await client.validate(key)
```

Sources: Windows `MachineGuid`, Linux `/etc/machine-id` (fallback `/var/lib/dbus/machine-id`), macOS `IOPlatformUUID`. Throws `SdkeyError` with `code: 'HWID_UNAVAILABLE'` on unsupported platforms, missing IDs, or non-Node runtimes.

`validate` calls `init()` automatically when no session exists. Sessions last ~15 minutes server-side; on `SESSION_EXPIRED` the client clears local state so the next call re-handshakes.

### Client auth (plaintext JSON)

```ts
const registered = await client.register({
  username: 'player1',
  password: '••••••••',
  licenseKey: 'SDKY-XXXX-XXXX-XXXX-XXXX', // may be required by app settings
  hwid: 'machine-hwid', // optional
})

const loggedIn = await client.login({
  username: 'player1',
  password: '••••••••',
})

// Upgrade = username + license key only (no password)
const upgraded = await client.upgrade({
  username: 'player1',
  licenseKey: 'SDKY-HIGHER-TIER-KEY',
})
```

Auth success returns `sessionToken`, `expiresAt`, `user`, `license`, and `session`. Failures throw `SdkeyError` with `code: 'AUTH_FAILED'`, `message` = server `error`, and `serverCode` = server `code`.

## Where `message` vs `error` appears

Per-app `responseMessages` override defaults. Clients receive those strings; they do not load settings themselves.

| Surface | Success text field | Failure text field |
|---|---|---|
| Session init | *(none)* | `error` |
| Sealed validate | `message` (`OK`) | `message` |
| Client register / login / upgrade | *(none)* | `error` |

### Sealed validate success

```json
{
  "success": true,
  "code": "OK",
  "message": "validated",
  "status": "active",
  "expiresAt": "2026-01-01T00:00:00.000Z",
  "subscriptionTier": 0,
  "sessionId": "...",
  "timestamp": 1720000001,
  "v": 1
}
```

### Sealed validate failure

```json
{
  "success": false,
  "code": "HWID_MISMATCH",
  "message": "Hardware ID mismatch",
  "status": null,
  "expiresAt": null,
  "sessionId": "...",
  "timestamp": 1720000001,
  "v": 1
}
```

### Session init / client auth failure

```json
{
  "success": false,
  "error": "Client version outdated",
  "code": "APP_OUTDATED"
}
```

## API

### `new SdkeyClient(options)`

| Option | Type | Description |
|---|---|---|
| `apiBaseUrl` | `string` | API origin (no trailing slash) |
| `appId` | `string` | Application UUID |
| `appVersion` | `string` | Exact app version → sent as `clientVersion` |
| `appPublicKeyB64` | `string` | Raw Ed25519 public key (32 bytes), base64 |
| `fetch` | `typeof fetch` | Optional fetch override (tests / custom agents) |

### Methods

- `init()` — challenge handshake; verifies the signed hello; derives the AES session key; sends `clientVersion`
- `validate(licenseKey, hwid?)` — sealed validate; omits `hwid` JSON key when not provided; **always** decrypts then verifies the Ed25519 signature before trusting `success`
- `register({ username, password, email?, licenseKey?, hwid? })` — plaintext client register
- `login({ username, password, hwid? })` — plaintext client login
- `upgrade({ username, licenseKey, hwid? })` — plaintext tier upgrade (**no password**)
- `getSession()` / `clearSession()` — inspect or drop the local crypto session

### Helpers

- `getHardwareId()` — Node-only stable HWID (SHA-256 hex of OS machine id); throw `HWID_UNAVAILABLE` in browsers / when unavailable

### Errors

Protocol / transport failures throw `SdkeyError` with a `code`:

`INIT_FAILED` · `HELLO_SIGNATURE_INVALID` · `VALIDATE_RESPONSE_INVALID` · `RESPONSE_SIGNATURE_INVALID` · `SESSION_MISMATCH` · `CLOCK_SKEW` · `AUTH_FAILED` · `NETWORK` · `HWID_UNAVAILABLE`

When the server returns a plaintext failure body, `err.message` is the server `error` string and `err.serverCode` is the server `code` (for example `APP_OUTDATED`, `TIER_NOT_HIGHER`).

License denials (banned, HWID mismatch, etc.) return a normal `ValidateResult` with `success: false` — they are not thrown. Sealed text is always in `message`.

## Security notes

- Never ship app **private** keys in a client.
- Do not skip signature verification — that is the anti-spoof binding.
- This package is open source; the SDKey server remains a separate product.
- This client SDK does **not** include developer tooling / Bearer management APIs.

## Development

```bash
pnpm install
pnpm test
pnpm build
```

## License

MIT
