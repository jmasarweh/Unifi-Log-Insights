import { describe, expect, it } from 'vitest'
import { isControllablePolicy } from '../lib/firewallPolicyLogging'

describe('isControllablePolicy', () => {
  it('allows enabled user policies with addressable ids', () => {
    expect(isControllablePolicy({
      id: '65f31c0a1234567890abcdef',
      enabled: true,
      metadata: { origin: 'USER_DEFINED' },
    })).toBe(true)
  })

  it('rejects policies without ids so PATCH cannot target undefined', () => {
    expect(isControllablePolicy({
      enabled: true,
      metadata: { origin: 'USER_DEFINED' },
    })).toBe(false)
    expect(isControllablePolicy({
      id: '',
      enabled: true,
      metadata: { origin: 'USER_DEFINED' },
    })).toBe(false)
  })

  it('keeps existing derived and disabled guards', () => {
    expect(isControllablePolicy({
      id: 'derived-policy',
      metadata: { origin: 'DERIVED' },
    })).toBe(false)
    expect(isControllablePolicy({
      id: 'disabled-policy',
      enabled: false,
      metadata: { origin: 'USER_DEFINED' },
    })).toBe(false)
  })
})
