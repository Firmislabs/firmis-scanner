import { describe, it, expect } from 'vitest'
import { FileAnalyzer } from '../../../src/scanner/analyzer.js'
import { MAX_CONTENT_SIZE } from '../../../src/scanner/constants.js'
import { writeFile, mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

describe('FileAnalyzer content size cap', () => {
  it('exports MAX_CONTENT_SIZE as 50KB', () => {
    expect(MAX_CONTENT_SIZE).toBe(50 * 1024)
  })

  it('truncates content larger than MAX_CONTENT_SIZE', async () => {
    const analyzer = new FileAnalyzer()
    const dir = await mkdtemp(join(tmpdir(), 'firmis-test-'))
    const filePath = join(dir, 'large.yaml')
    const largeContent = 'x'.repeat(MAX_CONTENT_SIZE + 1000)
    await writeFile(filePath, largeContent)

    try {
      const result = await analyzer.analyzeFile(filePath)
      expect(result.content.length).toBeLessThanOrEqual(MAX_CONTENT_SIZE)
      expect(result.contentTruncated).toBe(true)
    } finally {
      await rm(dir, { recursive: true })
    }
  })

  it('does not truncate content smaller than MAX_CONTENT_SIZE', async () => {
    const analyzer = new FileAnalyzer()
    const dir = await mkdtemp(join(tmpdir(), 'firmis-test-'))
    const filePath = join(dir, 'small.yaml')
    await writeFile(filePath, 'hello world')

    try {
      const result = await analyzer.analyzeFile(filePath)
      expect(result.content).toBe('hello world')
      expect(result.contentTruncated).toBeFalsy()
    } finally {
      await rm(dir, { recursive: true })
    }
  })

  it('truncates at last newline before cap', async () => {
    const analyzer = new FileAnalyzer()
    const dir = await mkdtemp(join(tmpdir(), 'firmis-test-'))
    const filePath = join(dir, 'lines.yaml')
    const lines = Array.from({ length: 2000 }, (_, i) => `line-${i}: ${'a'.repeat(30)}`)
    await writeFile(filePath, lines.join('\n'))

    try {
      const result = await analyzer.analyzeFile(filePath)
      expect(result.content.endsWith('\n')).toBe(true)
      expect(result.content.length).toBeLessThanOrEqual(MAX_CONTENT_SIZE)
      expect(result.contentTruncated).toBe(true)
    } finally {
      await rm(dir, { recursive: true })
    }
  })
})
