import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { SdkeyError } from './errors.js'

function isNodeRuntime(): boolean {
  return typeof process !== 'undefined' && typeof process.versions?.node === 'string'
}

/**
 * SHA-256 (lowercase hex) of the UTF-8 machine identifier after trim.
 * Rejects empty / whitespace-only input.
 */
export function hashMachineId(raw: string): string {
  const trimmed = raw.trim()
  if (!trimmed) {
    throw new SdkeyError('HWID_UNAVAILABLE', 'machine identifier is empty')
  }
  return createHash('sha256').update(trimmed, 'utf8').digest('hex')
}

function readWindowsMachineGuid(): string {
  let out: string
  try {
    out = execFileSync(
      'reg',
      ['query', 'HKLM\\SOFTWARE\\Microsoft\\Cryptography', '/v', 'MachineGuid'],
      { encoding: 'utf8' },
    )
  } catch (cause) {
    throw new SdkeyError('HWID_UNAVAILABLE', 'failed to read Windows MachineGuid', cause)
  }
  const match = /MachineGuid\s+REG_SZ\s+(\S+)/i.exec(out)
  if (!match?.[1]) {
    throw new SdkeyError('HWID_UNAVAILABLE', 'Windows MachineGuid not found')
  }
  return match[1]
}

function readLinuxMachineId(): string {
  for (const path of ['/etc/machine-id', '/var/lib/dbus/machine-id'] as const) {
    if (!existsSync(path)) continue
    try {
      return readFileSync(path, 'utf8')
    } catch (cause) {
      throw new SdkeyError('HWID_UNAVAILABLE', `failed to read ${path}`, cause)
    }
  }
  throw new SdkeyError('HWID_UNAVAILABLE', 'Linux machine-id not found')
}

function readMacOsPlatformUuid(): string {
  let out: string
  try {
    out = execFileSync('ioreg', ['-rd1', '-c', 'IOPlatformExpertDevice'], {
      encoding: 'utf8',
    })
  } catch (cause) {
    throw new SdkeyError('HWID_UNAVAILABLE', 'failed to read macOS IOPlatformUUID', cause)
  }
  const match = /"IOPlatformUUID"\s*=\s*"([^"]+)"/.exec(out)
  if (!match?.[1]) {
    throw new SdkeyError('HWID_UNAVAILABLE', 'macOS IOPlatformUUID not found')
  }
  return match[1]
}

/** Read the raw OS machine identifier (before hashing). Exported for tests. */
export function readRawMachineId(platform: NodeJS.Platform = process.platform): string {
  switch (platform) {
    case 'win32':
      return readWindowsMachineGuid()
    case 'linux':
      return readLinuxMachineId()
    case 'darwin':
      return readMacOsPlatformUuid()
    default:
      throw new SdkeyError(
        'HWID_UNAVAILABLE',
        `unsupported platform for getHardwareId(): ${platform}`,
      )
  }
}

/**
 * Stable hardware ID for desktop Node apps: SHA-256 hex of the OS machine identifier.
 *
 * Sources: Windows MachineGuid, Linux machine-id, macOS IOPlatformUUID.
 * Not available in browsers — omit `hwid` on validate / register / login / upgrade for web.
 *
 * @example
 * ```ts
 * await client.validate(key, getHardwareId())
 * ```
 */
export function getHardwareId(): string {
  if (!isNodeRuntime()) {
    throw new SdkeyError(
      'HWID_UNAVAILABLE',
      'getHardwareId() requires Node.js; omit hwid for web clients',
    )
  }
  return hashMachineId(readRawMachineId())
}
