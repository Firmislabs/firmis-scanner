import { describe, it, expect, vi, beforeEach } from 'vitest'
import { createFirmisServer } from '../../../src/mcp/server.js'

vi.mock('../../../src/reporters/html.js', () => ({
  HtmlReporter: vi.fn().mockImplementation(() => ({
    report: vi.fn().mockResolvedValue(undefined),
    getOutputPath: vi.fn().mockReturnValue('/tmp/firmis-report.html'),
  })),
}))

vi.mock('../../../src/scanner/engine.js', () => {
  const mockResult = {
    id: 'test-id',
    startedAt: new Date(),
    completedAt: new Date(),
    duration: 100,
    platforms: [],
    summary: {
      totalComponents: 0,
      threatsFound: 0,
      passedComponents: 0,
      failedComponents: 0,
      totalFiles: 0,
      filesAnalyzed: 0,
      filesNotAnalyzed: 0,
      bySeverity: { low: 0, medium: 0, high: 0, critical: 0 },
      byCategory: {},
    },
    score: 'A' as const,
    runtimeRisksNotCovered: [],
  }

  return {
    ScanEngine: vi.fn().mockImplementation(() => ({
      initialize: vi.fn().mockResolvedValue(undefined),
      scan: vi.fn().mockResolvedValue(mockResult),
    })),
  }
})

describe('Firmis MCP Server', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('creates a server instance', () => {
    const server = createFirmisServer()
    expect(server).toBeDefined()
  })

  it('registers the firmis_scan tool without throwing', () => {
    expect(() => createFirmisServer()).not.toThrow()
  })

  it('exposes firmis_scan tool on the server', () => {
    const server = createFirmisServer()
    // McpServer stores registered tools on a plain object keyed by tool name
    const internalTools = (
      server as unknown as { _registeredTools: Record<string, unknown> }
    )._registeredTools
    expect('firmis_scan' in internalTools).toBe(true)
  })

  it('exposes firmis_report tool on the server', () => {
    const server = createFirmisServer()
    const internalTools = (
      server as unknown as { _registeredTools: Record<string, unknown> }
    )._registeredTools
    expect('firmis_report' in internalTools).toBe(true)
  })

  it('exposes firmis_discover tool on the server', () => {
    const server = createFirmisServer()
    const internalTools = (
      server as unknown as { _registeredTools: Record<string, unknown> }
    )._registeredTools
    expect('firmis_discover' in internalTools).toBe(true)
  })
})
