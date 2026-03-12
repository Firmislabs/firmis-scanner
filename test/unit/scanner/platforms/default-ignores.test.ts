import { describe, it, expect } from 'vitest'
import { BasePlatformAnalyzer } from '../../../../src/scanner/platforms/base.js'
import type { DiscoveredComponent, ComponentMetadata, DetectedPlatform } from '../../../../src/types/index.js'

class TestAnalyzer extends BasePlatformAnalyzer {
  readonly platformType = 'claude' as const
  readonly name = 'test'
  async detect(): Promise<DetectedPlatform[]> { return [] }
  async discover(): Promise<DiscoveredComponent[]> { return [] }
  async analyze(): Promise<string[]> { return [] }
  async getMetadata(): Promise<ComponentMetadata> { return {} }
}

describe('BasePlatformAnalyzer.getIgnorePatterns', () => {
  it('returns standard ignore patterns', async () => {
    const analyzer = new TestAnalyzer()
    const patterns = await (analyzer as any).getIgnorePatterns(process.cwd())
    expect(patterns).toContain('**/node_modules/**')
    expect(patterns).toContain('**/.git/**')
    expect(patterns).toContain('**/venv/**')
    expect(patterns).toContain('**/__pycache__/**')
  })

  it('always includes core patterns regardless of root path', async () => {
    const analyzer = new TestAnalyzer()
    const patterns = await (analyzer as any).getIgnorePatterns('/nonexistent/path')
    expect(patterns).toContain('**/node_modules/**')
    expect(patterns).toContain('**/.git/**')
  })

  it('returns an array of strings', async () => {
    const analyzer = new TestAnalyzer()
    const patterns = await (analyzer as any).getIgnorePatterns(process.cwd())
    expect(Array.isArray(patterns)).toBe(true)
    for (const p of patterns) {
      expect(typeof p).toBe('string')
    }
  })
})
