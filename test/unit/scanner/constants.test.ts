import { describe, it, expect } from 'vitest'
import { DEFAULT_IGNORE_GLOBS } from '../../../src/scanner/constants.js'

describe('DEFAULT_IGNORE_GLOBS', () => {
  it('exports a non-empty array of glob strings', () => {
    expect(Array.isArray(DEFAULT_IGNORE_GLOBS)).toBe(true)
    expect(DEFAULT_IGNORE_GLOBS.length).toBeGreaterThan(0)
    for (const pattern of DEFAULT_IGNORE_GLOBS) {
      expect(typeof pattern).toBe('string')
    }
  })

  it('includes common build output directories', () => {
    expect(DEFAULT_IGNORE_GLOBS).toContain('**/dist/**')
    expect(DEFAULT_IGNORE_GLOBS).toContain('**/build/**')
    expect(DEFAULT_IGNORE_GLOBS).toContain('**/out/**')
  })

  it('includes dependency directories', () => {
    expect(DEFAULT_IGNORE_GLOBS).toContain('**/node_modules/**')
    expect(DEFAULT_IGNORE_GLOBS).toContain('**/.git/**')
    expect(DEFAULT_IGNORE_GLOBS).toContain('**/venv/**')
    expect(DEFAULT_IGNORE_GLOBS).toContain('**/.venv/**')
    expect(DEFAULT_IGNORE_GLOBS).toContain('**/__pycache__/**')
    expect(DEFAULT_IGNORE_GLOBS).toContain('**/vendor/**')
  })

  it('includes minified and generated files', () => {
    expect(DEFAULT_IGNORE_GLOBS).toContain('**/*.min.js')
    expect(DEFAULT_IGNORE_GLOBS).toContain('**/*.min.css')
    expect(DEFAULT_IGNORE_GLOBS).toContain('**/*.d.ts')
    expect(DEFAULT_IGNORE_GLOBS).toContain('**/*.map')
  })

  it('includes lock files', () => {
    expect(DEFAULT_IGNORE_GLOBS).toContain('**/package-lock.json')
    expect(DEFAULT_IGNORE_GLOBS).toContain('**/yarn.lock')
    expect(DEFAULT_IGNORE_GLOBS).toContain('**/pnpm-lock.yaml')
    expect(DEFAULT_IGNORE_GLOBS).toContain('**/Cargo.lock')
    expect(DEFAULT_IGNORE_GLOBS).toContain('**/poetry.lock')
  })

  it('includes test coverage and CI artifacts', () => {
    expect(DEFAULT_IGNORE_GLOBS).toContain('**/coverage/**')
    expect(DEFAULT_IGNORE_GLOBS).toContain('**/.nyc_output/**')
    expect(DEFAULT_IGNORE_GLOBS).toContain('**/.cache/**')
  })

  it('includes IDE and OS files', () => {
    expect(DEFAULT_IGNORE_GLOBS).toContain('**/.idea/**')
    expect(DEFAULT_IGNORE_GLOBS).toContain('**/.vscode/**')
    expect(DEFAULT_IGNORE_GLOBS).toContain('**/.DS_Store')
    expect(DEFAULT_IGNORE_GLOBS).toContain('**/Thumbs.db')
  })
})
