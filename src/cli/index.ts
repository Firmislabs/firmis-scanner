#!/usr/bin/env node

import { Command } from 'commander'
import { scanCommand } from './commands/scan.js'
import { listCommand } from './commands/list.js'
import { validateCommand } from './commands/validate.js'
import { discoverCommand } from './commands/discover.js'
import { bomCommand } from './commands/bom.js'
import { ciCommand } from './commands/ci.js'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

async function getVersion(): Promise<string> {
  try {
    const packagePath = join(__dirname, '../../package.json')
    const content = await readFile(packagePath, 'utf-8')
    const pkg = JSON.parse(content)
    return pkg.version || '1.0.0'
  } catch {
    return '1.0.0'
  }
}

async function main(): Promise<void> {
  // Launch MCP server if --mcp flag is passed
  if (process.argv.includes('--mcp')) {
    const { StdioServerTransport } = await import('@modelcontextprotocol/sdk/server/stdio.js')
    const { createFirmisServer } = await import('../mcp/server.js')
    const server = createFirmisServer()
    const transport = new StdioServerTransport()
    await server.connect(transport)
    return
  }

  const version = await getVersion()

  const program = new Command()

  program
    .name('firmis')
    .description('AI agent runtime security scanner')
    .version(version, '-v, --version', 'Display version number')

  program.addCommand(scanCommand)
  program.addCommand(listCommand)
  program.addCommand(validateCommand)
  program.addCommand(discoverCommand)
  program.addCommand(bomCommand)
  program.addCommand(ciCommand)
  await program.parseAsync(process.argv)
}

main().catch((error) => {
  console.error('Fatal error:', error.message)
  process.exit(1)
})
