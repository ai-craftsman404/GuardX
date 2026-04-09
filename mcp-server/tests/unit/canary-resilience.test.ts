import { describe, it, expect } from 'vitest'
import { checkCanary } from '../../src/canary.js'

describe('canary resilience — checkCanary unit tests', () => {
  it('exact token in extractedContent → triggered', () => {
    const token = 'GX-test1234abcd'
    const scanResult = {
      findings: [
        {
          extractedContent: `Here is the token: ${token} for verification`
        }
      ],
      extractedFragments: []
    }
    const result = checkCanary(token, scanResult)
    expect(result.triggered).toBe(true)
    expect(result.foundIn).toContain('findings.extractedContent')
  })

  it('exact token in extractedFragments → triggered', () => {
    const token = 'GX-frag5678efgh'
    const scanResult = {
      findings: [],
      extractedFragments: [
        `Prefix text ${token} suffix text`
      ]
    }
    const result = checkCanary(token, scanResult)
    expect(result.triggered).toBe(true)
    expect(result.foundIn).toContain('extractedFragments')
  })

  it('token uppercased → NOT triggered', () => {
    const token = 'GX-abcd1234'
    const scanResult = {
      findings: [
        {
          extractedContent: `Found: GX-ABCD1234`
        }
      ],
      extractedFragments: []
    }
    const result = checkCanary(token, scanResult)
    expect(result.triggered).toBe(false)
    expect(result.foundIn).toHaveLength(0)
  })

  it('token with 1 char changed → NOT triggered', () => {
    const token = 'GX-abcd1234'
    const scanResult = {
      findings: [
        {
          extractedContent: `Found: GX-abcd1235`
        }
      ],
      extractedFragments: []
    }
    const result = checkCanary(token, scanResult)
    expect(result.triggered).toBe(false)
    expect(result.foundIn).toHaveLength(0)
  })

  it('token buried in surrounding noise → triggered', () => {
    const token = 'GX-noise9999wxyz'
    const scanResult = {
      findings: [
        {
          extractedContent: `some prefix some more noise ${token} some suffix more noise here`
        }
      ],
      extractedFragments: []
    }
    const result = checkCanary(token, scanResult)
    expect(result.triggered).toBe(true)
    expect(result.foundIn).toContain('findings.extractedContent')
  })

  it('token inside JSON string → triggered', () => {
    const token = 'GX-json1111kkkk'
    const scanResult = {
      findings: [
        {
          extractedContent: JSON.stringify({ value: token, type: 'canary' })
        }
      ],
      extractedFragments: []
    }
    const result = checkCanary(token, scanResult)
    expect(result.triggered).toBe(true)
    expect(result.foundIn).toContain('findings.extractedContent')
  })

  it('two canaries in one scan → each detected independently', () => {
    const token1 = 'GX-first2222aaaa'
    const token2 = 'GX-second3333bbbb'
    const scanResult = {
      findings: [
        { extractedContent: `Token: ${token1}` },
        { extractedContent: `Another: ${token2}` }
      ],
      extractedFragments: []
    }

    const result1 = checkCanary(token1, scanResult)
    expect(result1.triggered).toBe(true)
    expect(result1.foundIn).toContain('findings.extractedContent')

    const result2 = checkCanary(token2, scanResult)
    expect(result2.triggered).toBe(true)
    expect(result2.foundIn).toContain('findings.extractedContent')
  })

  it('wrong token checked against scan with different canary → NOT triggered', () => {
    const tokenInScan = 'GX-aaaabbbb'
    const tokenToCheck = 'GX-ccccdddd'
    const scanResult = {
      findings: [
        {
          extractedContent: `Scan has: ${tokenInScan}`
        }
      ],
      extractedFragments: []
    }
    const result = checkCanary(tokenToCheck, scanResult)
    expect(result.triggered).toBe(false)
    expect(result.foundIn).toHaveLength(0)
  })

  it('empty/null extractedContent fields → no crash, triggered: false', () => {
    const token = 'GX-safe4444qqqq'
    const scanResult = {
      findings: [
        { extractedContent: null },
        { extractedContent: undefined },
        { extractedContent: '' }
      ],
      extractedFragments: []
    }
    const result = checkCanary(token, scanResult)
    expect(result.triggered).toBe(false)
    expect(result.foundIn).toHaveLength(0)
  })

  it('token only in extractedFragments not findings → foundIn has only extractedFragments', () => {
    const token = 'GX-onlyfrag5555'
    const scanResult = {
      findings: [
        { extractedContent: 'no token here' },
        { extractedContent: 'also no token' }
      ],
      extractedFragments: [
        `Fragment contains ${token} token`
      ]
    }
    const result = checkCanary(token, scanResult)
    expect(result.triggered).toBe(true)
    expect(result.foundIn).toEqual(['extractedFragments'])
    expect(result.foundIn).not.toContain('findings.extractedContent')
  })

  it('token present in both extractedContent AND extractedFragments → foundIn contains both', () => {
    const token = 'GX-both6666zzzz'
    const scanResult = {
      findings: [
        { extractedContent: `Found token: ${token}` }
      ],
      extractedFragments: [
        `Also found: ${token}`
      ]
    }
    const result = checkCanary(token, scanResult)
    expect(result.triggered).toBe(true)
    expect(result.foundIn).toContain('findings.extractedContent')
    expect(result.foundIn).toContain('extractedFragments')
  })

  it('same token in two separate findings → foundIn has two findings.extractedContent entries', () => {
    const token = 'GX-multi7777yyyy'
    const scanResult = {
      findings: [
        { extractedContent: `First: ${token}` },
        { extractedContent: `Second: ${token}` }
      ],
      extractedFragments: []
    }
    const result = checkCanary(token, scanResult)
    expect(result.triggered).toBe(true)
    expect(result.foundIn).toHaveLength(2)
    expect(result.foundIn[0]).toBe('findings.extractedContent')
    expect(result.foundIn[1]).toBe('findings.extractedContent')
  })
})
