import { createHash } from 'node:crypto'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { SdkeyError } from '../src/errors.js'
import { getHardwareId, hashMachineId, readRawMachineId } from '../src/hwid.js'

vi.mock('node:child_process', () => ({
  execFileSync: vi.fn(),
}))

vi.mock('node:fs', () => ({
  existsSync: vi.fn(),
  readFileSync: vi.fn(),
}))

import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'

const execFileSyncMock = vi.mocked(execFileSync)
const existsSyncMock = vi.mocked(existsSync)
const readFileSyncMock = vi.mocked(readFileSync)

describe('hashMachineId', () => {
  it('returns lowercase SHA-256 hex of trimmed UTF-8 input', () => {
    const raw = '  fixture-machine-id\n'
    const expected = createHash('sha256').update('fixture-machine-id', 'utf8').digest('hex')
    expect(hashMachineId(raw)).toBe(expected)
    expect(hashMachineId(raw)).toMatch(/^[0-9a-f]{64}$/)
  })

  it('rejects empty or whitespace-only input', () => {
    expect(() => hashMachineId('')).toThrowError(SdkeyError)
    expect(() => hashMachineId('   \n\t  ')).toThrowError(
      expect.objectContaining({ code: 'HWID_UNAVAILABLE' }),
    )
  })
})

describe('readRawMachineId', () => {
  beforeEach(() => {
    execFileSyncMock.mockReset()
    existsSyncMock.mockReset()
    readFileSyncMock.mockReset()
  })

  it('reads Windows MachineGuid via reg query', () => {
    execFileSyncMock.mockReturnValue(
      [
        '',
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography',
        '    MachineGuid    REG_SZ    aabbccdd-eeff-0011-2233-445566778899',
        '',
      ].join('\n'),
    )
    expect(readRawMachineId('win32')).toBe('aabbccdd-eeff-0011-2233-445566778899')
    expect(execFileSyncMock).toHaveBeenCalledWith(
      'reg',
      ['query', 'HKLM\\SOFTWARE\\Microsoft\\Cryptography', '/v', 'MachineGuid'],
      { encoding: 'utf8' },
    )
  })

  it('reads Linux /etc/machine-id when present', () => {
    existsSyncMock.mockImplementation((p) => p === '/etc/machine-id')
    readFileSyncMock.mockReturnValue('linux-machine-id\n')
    expect(readRawMachineId('linux')).toBe('linux-machine-id\n')
    expect(readFileSyncMock).toHaveBeenCalledWith('/etc/machine-id', 'utf8')
  })

  it('falls back to dbus machine-id on Linux', () => {
    existsSyncMock.mockImplementation((p) => p === '/var/lib/dbus/machine-id')
    readFileSyncMock.mockReturnValue('dbus-machine-id')
    expect(readRawMachineId('linux')).toBe('dbus-machine-id')
  })

  it('reads macOS IOPlatformUUID via ioreg', () => {
    execFileSyncMock.mockReturnValue(
      '  "IOPlatformUUID" = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"\n',
    )
    expect(readRawMachineId('darwin')).toBe('AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE')
    expect(execFileSyncMock).toHaveBeenCalledWith(
      'ioreg',
      ['-rd1', '-c', 'IOPlatformExpertDevice'],
      { encoding: 'utf8' },
    )
  })

  it('throws on unsupported platforms', () => {
    expect(() => readRawMachineId('freebsd')).toThrowError(
      expect.objectContaining({
        name: 'SdkeyError',
        code: 'HWID_UNAVAILABLE',
      }),
    )
  })

  it('throws when Linux machine-id files are missing', () => {
    existsSyncMock.mockReturnValue(false)
    expect(() => readRawMachineId('linux')).toThrowError(
      expect.objectContaining({ code: 'HWID_UNAVAILABLE' }),
    )
  })
})

describe('getHardwareId', () => {
  beforeEach(() => {
    execFileSyncMock.mockReset()
    existsSyncMock.mockReset()
    readFileSyncMock.mockReset()
  })

  it('hashes the OS machine identifier for the current platform', () => {
    if (process.platform === 'win32') {
      execFileSyncMock.mockReturnValue(
        '    MachineGuid    REG_SZ    test-guid-for-hwid\n',
      )
    } else if (process.platform === 'linux') {
      existsSyncMock.mockImplementation((p) => p === '/etc/machine-id')
      readFileSyncMock.mockReturnValue('test-guid-for-hwid')
    } else if (process.platform === 'darwin') {
      execFileSyncMock.mockReturnValue('"IOPlatformUUID" = "test-guid-for-hwid"\n')
    } else {
      // Skip assertion path on exotic CI hosts; unsupported platforms throw.
      expect(() => getHardwareId()).toThrowError(SdkeyError)
      return
    }

    const expected = createHash('sha256').update('test-guid-for-hwid', 'utf8').digest('hex')
    expect(getHardwareId()).toBe(expected)
  })
})
