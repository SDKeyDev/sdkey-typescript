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
  appPublicKeyB64: process.env.SDKEY_APP_PUBLIC_KEY_B64 ?? '',
})

async function main() {
  const licenseKey = process.env.SDKEY_LICENSE_KEY ?? 'SDKY-XXXX-XXXX-XXXX-XXXX'
  const hwid = process.env.SDKEY_HWID ?? 'example-machine-1'

  try {
    const result = await client.validate(licenseKey, hwid)
    console.log(result)
  } catch (err) {
    if (err instanceof SdkeyError) {
      console.error(`[${err.code}] ${err.message}`)
      process.exitCode = 1
      return
    }
    throw err
  }
}

void main()
