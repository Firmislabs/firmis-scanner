import { describe, it, expect } from 'vitest'
import { createEmptySummary } from '../../../src/types/scan.js'
import type { ThreatCategory } from '../../../src/types/scan.js'

describe('cross-agent-propagation category', () => {
  it('is a valid ThreatCategory', () => {
    const category: ThreatCategory = 'cross-agent-propagation'
    expect(category).toBe('cross-agent-propagation')
  })

  it('is included in createEmptySummary byCategory', () => {
    const summary = createEmptySummary()
    expect(summary.byCategory['cross-agent-propagation']).toBe(0)
  })
})
