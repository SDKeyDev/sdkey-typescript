/**
 * Minimal usage example. Replace placeholders with values from the SDKey dashboard.
 *
 *   pnpm build
 *   node --experimental-strip-types examples/basic.ts
 */
import { SdkeyClient, SdkeyError } from '../src/index.js'

const client = new SdkeyClient({
  apiBaseUrl: process.env.SDKEY_API_BASE_URL ?? 'https://api.sdkey.dev',
  appId: process.env.SDKEY_APP_ID ?? '00000000-0000-0000-0000-000000000000',
  appVersion: process.env.SDKEY_APP_VERSION ?? '1.0.0',
  appPublicKeyB64: process.env.SDKEY_APP_PUBLIC_KEY_B64 ?? '',
})

async function main() {
  const licenseKey = process.env.SDKEY_LICENSE_KEY ?? 'SDKY-XXXX-XXXX-XXXX-XXXX'
  // Omit SDKEY_HWID for web-style validate (no hwid key in the sealed payload).
  const hwid = process.env.SDKEY_HWID

  try {
    const result =
      hwid !== undefined && hwid !== ''
        ? await client.validate(licenseKey, hwid)
        : await client.validate(licenseKey)

    if (result.success) {
      console.log('ok', {
        status: result.status,
        expiresAt: result.expiresAt,
        subscriptionTier: result.subscriptionTier,
        message: result.message,
      })
    } else {
      console.error('denied', { code: result.code, message: result.message })
      process.exitCode = 1
    }
  } catch (err) {
    if (err instanceof SdkeyError) {
      console.error(`[${err.code}] ${err.message}`, err.serverCode ?? '')
      process.exitCode = 1
      return
    }
    throw err
  }
}

void main()
