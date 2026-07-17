export type SdkeyErrorCode =
  | 'INIT_FAILED'
  | 'HELLO_SIGNATURE_INVALID'
  | 'VALIDATE_RESPONSE_INVALID'
  | 'RESPONSE_SIGNATURE_INVALID'
  | 'SESSION_MISMATCH'
  | 'CLOCK_SKEW'
  | 'NETWORK'
  | 'UNKNOWN'

export class SdkeyError extends Error {
  readonly code: SdkeyErrorCode

  constructor(code: SdkeyErrorCode, message: string, cause?: unknown) {
    super(message, cause !== undefined ? { cause } : undefined)
    this.name = 'SdkeyError'
    this.code = code
  }
}
