#!/usr/bin/env node

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { createFirmisServer } from './server.js'

async function main(): Promise<void> {
  const server = createFirmisServer()
  const transport = new StdioServerTransport()
  await server.connect(transport)
}

main().catch((error: unknown) => {
  console.error('Firmis MCP server failed to start:', error)
  process.exit(1)
})
