import { describe, it, expect, beforeEach } from 'vitest'
import { RuleEngine } from '../../../src/rules/engine.js'

describe('agent-config-integrity rules', () => {
  let engine: RuleEngine

  beforeEach(async () => {
    engine = new RuleEngine()
    await engine.load()
  })

  // ---------------------------------------------------------------------------
  // Rule loading
  // ---------------------------------------------------------------------------

  it('should load aci-001 rule', () => {
    const rules = engine.getRules()
    const rule = rules.find(r => r.id === 'aci-001')
    expect(rule).toBeDefined()
    expect(rule!.category).toBe('insecure-config')
    expect(rule!.severity).toBe('critical')
  })

  it('should load aci-002 rule', () => {
    const rules = engine.getRules()
    const rule = rules.find(r => r.id === 'aci-002')
    expect(rule).toBeDefined()
    expect(rule!.category).toBe('agent-memory-poisoning')
    expect(rule!.severity).toBe('high')
  })

  // ---------------------------------------------------------------------------
  // aci-001: Agent Config Tampering
  // ---------------------------------------------------------------------------

  describe('aci-001 — agent config tampering', () => {
    it('detects write operations to IDENTITY.md', async () => {
      const content = 'fs.writeFileSync("IDENTITY.md", attackerPayload)'
      const threats = await engine.analyze(content, 'setup.ts', null, 'claude')
      const matches = threats.filter(t => t.ruleId === 'aci-001')
      expect(matches.length).toBeGreaterThan(0)
      expect(matches[0]!.category).toBe('insecure-config')
      expect(matches[0]!.severity).toBe('critical')
    })

    it('detects write operations to SOUL.md', async () => {
      const content = 'writeFile("SOUL.md", injectedContent)'
      const threats = await engine.analyze(content, 'agent.ts', null, 'openclaw')
      const matches = threats.filter(t => t.ruleId === 'aci-001')
      expect(matches.length).toBeGreaterThan(0)
    })

    it('detects write operations to BOOTSTRAP.md', async () => {
      const content = 'overwrite("BOOTSTRAP.md", maliciousInstructions)'
      const threats = await engine.analyze(content, 'init.sh', null, 'claude')
      const matches = threats.filter(t => t.ruleId === 'aci-001')
      expect(matches.length).toBeGreaterThan(0)
    })

    it('detects tool definitions granting write access to identity files', async () => {
      const content = 'writeFile("path/to/SOUL", content)'
      const threats = await engine.analyze(content, 'tool-def.ts', null, 'mcp')
      const matches = threats.filter(t => t.ruleId === 'aci-001')
      expect(matches.length).toBeGreaterThan(0)
    })

    it('detects write_config tool name', async () => {
      const content = '"name": "write_config"'
      const threats = await engine.analyze(content, 'mcp-tool.json', null, 'mcp')
      const matches = threats.filter(t => t.ruleId === 'aci-001')
      expect(matches.length).toBeGreaterThan(0)
    })

    it('does not flag read-only access to identity files (safe)', async () => {
      const content = 'fs.readFileSync("IDENTITY.md", "utf-8")'
      const threats = await engine.analyze(content, 'loader.ts', null, 'claude')
      const matches = threats.filter(t => t.ruleId === 'aci-001')
      expect(matches.length).toBe(0)
    })
  })

  // ---------------------------------------------------------------------------
  // aci-002: Agent Memory Injection
  // ---------------------------------------------------------------------------

  describe('aci-002 — agent memory injection', () => {
    it('detects write operations to MEMORY.md', async () => {
      const content = 'write("MEMORY.md", externalInput)'
      const threats = await engine.analyze(content, 'handler.ts', null, 'claude')
      const matches = threats.filter(t => t.ruleId === 'aci-002')
      expect(matches.length).toBeGreaterThan(0)
      expect(matches[0]!.category).toBe('agent-memory-poisoning')
      expect(matches[0]!.severity).toBe('high')
    })

    it('detects append operations to memory directory', async () => {
      const content = 'appendToFile("memory/session.md", content)'
      const threats = await engine.analyze(content, 'session.ts', null, 'claude')
      const matches = threats.filter(t => t.ruleId === 'aci-002')
      expect(matches.length).toBeGreaterThan(0)
    })

    it('detects write access to long-term memory', async () => {
      const content = 'file_write("long_term_memory", userMessage)'
      const threats = await engine.analyze(content, 'memory.ts', null, 'crewai')
      const matches = threats.filter(t => t.ruleId === 'aci-002')
      expect(matches.length).toBeGreaterThan(0)
    })

    it('detects memory append from untrusted user_input sources', async () => {
      const content = 'user_input.forEach(item => memory.append(item))'
      const threats = await engine.analyze(content, 'agent.ts', null, 'openclaw')
      const matches = threats.filter(t => t.ruleId === 'aci-002')
      expect(matches.length).toBeGreaterThan(0)
    })

    it('detects inject_memory tool name', async () => {
      const content = '"name": "inject_memory"'
      const threats = await engine.analyze(content, 'tool.json', null, 'mcp')
      const matches = threats.filter(t => t.ruleId === 'aci-002')
      expect(matches.length).toBeGreaterThan(0)
    })

    it('does not flag read-only memory access (safe)', async () => {
      const content = 'const mem = await readFile("MEMORY.md", "utf-8")'
      const threats = await engine.analyze(content, 'reader.ts', null, 'claude')
      const matches = threats.filter(t => t.ruleId === 'aci-002')
      expect(matches.length).toBe(0)
    })
  })
})
