import { join } from 'node:path'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { z } from 'zod'
import { ScanEngine } from '../scanner/engine.js'
import { HtmlReporter } from '../reporters/html.js'
import type { FirmisConfig, SeverityLevel, PlatformType } from '../types/config.js'
import type { ScanResult } from '../types/scan.js'
import type { ScanToolOutput, DiscoverToolOutput } from './types.js'
import { sanitizeMcpOutput } from './sanitize.js'

const PLATFORMS = [
  'claude',
  'mcp',
  'codex',
  'cursor',
  'crewai',
  'autogpt',
  'openclaw',
  'nanobot',
] as const

const SEVERITIES = ['low', 'medium', 'high', 'critical'] as const

const ScanParamsSchema = {
  path: z.string().optional().describe('Target path to scan'),
  platform: z.enum(PLATFORMS).optional().describe('Specific platform to scan'),
  severity: z.enum(SEVERITIES).optional().describe('Minimum severity level'),
}

function buildScanConfig(params: {
  path?: string
  platform?: PlatformType
  severity?: SeverityLevel
}): FirmisConfig {
  return {
    targetPath: params.path,
    platforms: params.platform ? [params.platform] : undefined,
    severity: params.severity ?? 'low',
    output: 'json',
    verbose: false,
    concurrency: 4,
  }
}

function mapScanResult(result: ScanResult): ScanToolOutput {
  const allThreats = result.platforms.flatMap(p => p.threats)
  return {
    grade: result.score,
    threatsFound: result.summary.threatsFound,
    platformsScanned: result.platforms.length,
    componentsScanned: result.summary.totalComponents,
    threats: allThreats.map(t => ({
      ruleId: t.ruleId,
      category: t.category,
      severity: t.severity,
      message: t.message,
      location: `${t.location.file}:${t.location.line}`,
      confidence: t.confidence,
    })),
  }
}

export function createFirmisServer(): McpServer {
  const server = new McpServer({
    name: 'firmis',
    version: '1.4.1',
  })

  server.tool(
    'firmis_scan',
    'Scan AI agent configurations for security threats',
    ScanParamsSchema,
    async (params) => {
      const config = buildScanConfig(params)
      const engine = new ScanEngine(config)
      await engine.initialize()
      const result = await engine.scan()
      const output = mapScanResult(result)
      return {
        content: [{ type: 'text', text: sanitizeMcpOutput(JSON.stringify(output, null, 2)) }],
      }
    }
  )

  server.tool(
    'firmis_discover',
    'Discover installed AI agent platforms and their components',
    { path: z.string().optional().describe('Path to search') },
    async (params) => {
      const config: FirmisConfig = {
        targetPath: params.path,
        severity: 'critical',
        output: 'json',
        verbose: false,
        concurrency: 4,
      }
      const engine = new ScanEngine(config)
      await engine.initialize()
      const result = await engine.scan()
      const output: DiscoverToolOutput = {
        platforms: result.platforms.map(p => ({
          name: p.platform,
          type: p.platform,
          componentsFound: p.components.length,
          components: p.components.map(c => c.name),
        })),
      }
      return {
        content: [{ type: 'text', text: sanitizeMcpOutput(JSON.stringify(output, null, 2)) }],
      }
    }
  )

  server.tool(
    'firmis_report',
    'Run security scan and generate HTML report',
    {
      path: z.string().optional().describe('Path to scan'),
      platform: z.enum(PLATFORMS).optional().describe('Platform to scan'),
      severity: z.enum(SEVERITIES).optional().describe('Minimum severity'),
      outputPath: z.string().optional().describe('Where to save the HTML report'),
    },
    async (params) => {
      const config = buildScanConfig(params)
      const engine = new ScanEngine(config)
      await engine.initialize()
      const result = await engine.scan()

      const targetPath = config.targetPath ?? process.cwd()
      const reportFile = params.outputPath ?? join(targetPath, 'firmis-report.html')
      const reporter = new HtmlReporter(reportFile)
      await reporter.report(result)

      const summary = [
        `Security Grade: ${result.score}`,
        `Threats: ${result.summary.threatsFound}`,
        `Platforms: ${result.platforms.length}`,
        `Report: ${reportFile}`,
      ].join('\n')

      return { content: [{ type: 'text', text: sanitizeMcpOutput(summary) }] }
    }
  )

  return server
}
