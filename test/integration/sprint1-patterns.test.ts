import { describe, it, expect, beforeAll } from 'vitest'
import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'
import { RuleEngine } from '../../src/rules/engine.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const fixturesPath = path.join(__dirname, '../fixtures')
const samplesPath = path.join(__dirname, '../../samples')

describe('Integration: Sprint 1 - Pattern Detection', () => {
  let ruleEngine: RuleEngine

  beforeAll(async () => {
    ruleEngine = new RuleEngine()
    await ruleEngine.load()
  })

  describe('Malware Distribution Patterns', () => {
    it('detects malware distribution patterns in curl-pipe.js', async () => {
      const contentPath = path.join(fixturesPath, 'malware-patterns/curl-pipe-skill/curl-pipe.js')
      const analyzePath = path.join(samplesPath, 'malware-patterns/curl-pipe-skill/curl-pipe.js')
      const content = await fs.readFile(contentPath, 'utf-8')

      const threats = await ruleEngine.analyze(content, analyzePath, null, 'openclaw')

      const malwareThreats = threats.filter((t) => t.category === 'malware-distribution')
      expect(malwareThreats.length).toBeGreaterThan(0)

      const threatRuleIds = new Set(malwareThreats.map((t) => t.ruleId))
      const hasCurlPipe = Array.from(threatRuleIds).some((id) => id.includes('malware'))
      expect(hasCurlPipe).toBe(true)
    })

    it('detects curl pipe to bash pattern', async () => {
      const contentPath = path.join(fixturesPath, 'malware-patterns/curl-pipe-skill/curl-pipe.js')
      const analyzePath = path.join(samplesPath, 'malware-patterns/curl-pipe-skill/curl-pipe.js')
      const content = await fs.readFile(contentPath, 'utf-8')

      const threats = await ruleEngine.analyze(content, analyzePath, null, 'openclaw')

      const curlPipeThreat = threats.find((t) =>
        t.evidence.some((e) => e.snippet.includes('curl') && e.snippet.includes('bash'))
      )

      expect(curlPipeThreat).toBeDefined()
      expect(curlPipeThreat?.severity).toMatch(/high|critical/)
    })

    it('detects base64 decode eval pattern', async () => {
      const contentPath = path.join(fixturesPath, 'malware-patterns/curl-pipe-skill/curl-pipe.js')
      const analyzePath = path.join(samplesPath, 'malware-patterns/curl-pipe-skill/curl-pipe.js')
      const content = await fs.readFile(contentPath, 'utf-8')

      const threats = await ruleEngine.analyze(content, analyzePath, null, 'openclaw')

      const base64Threat = threats.find((t) =>
        t.evidence.some((e) => e.snippet.includes('base64') && e.snippet.includes('eval'))
      )

      expect(base64Threat).toBeDefined()
    })

    it('detects password-protected zip extraction', async () => {
      const contentPath = path.join(fixturesPath, 'malware-patterns/curl-pipe-skill/curl-pipe.js')
      const analyzePath = path.join(samplesPath, 'malware-patterns/curl-pipe-skill/curl-pipe.js')
      const content = await fs.readFile(contentPath, 'utf-8')

      const threats = await ruleEngine.analyze(content, analyzePath, null, 'openclaw')

      const unzipThreat = threats.find((t) =>
        t.evidence.some((e) => e.snippet.includes('unzip -P'))
      )

      expect(unzipThreat).toBeDefined()
    })

    it('detects systemctl service installation', async () => {
      const contentPath = path.join(fixturesPath, 'malware-patterns/curl-pipe-skill/curl-pipe.js')
      const analyzePath = path.join(samplesPath, 'malware-patterns/curl-pipe-skill/curl-pipe.js')
      const content = await fs.readFile(contentPath, 'utf-8')

      const threats = await ruleEngine.analyze(content, analyzePath, null, 'openclaw')

      const systemctlThreat = threats.find((t) =>
        t.evidence.some((e) => e.snippet.includes('systemctl'))
      )

      expect(systemctlThreat).toBeDefined()
    })

    it('safe script has no malware findings', async () => {
      const contentPath = path.join(fixturesPath, 'malware-patterns/safe-script-skill/safe-script.js')
      const analyzePath = path.join(samplesPath, 'malware-patterns/safe-script-skill/safe-script.js')
      const content = await fs.readFile(contentPath, 'utf-8')

      const threats = await ruleEngine.analyze(content, analyzePath, null, 'openclaw')

      const malwareThreats = threats.filter((t) => t.category === 'malware-distribution')
      expect(malwareThreats.length).toBe(0)
    })
  })

  describe('Memory Poisoning Patterns', () => {
    it('detects memory poisoning patterns in memory-writer.js', async () => {
      const contentPath = path.join(fixturesPath, 'memory-poisoning/memory-poisoning-skill/memory-writer.js')
      const analyzePath = path.join(samplesPath, 'memory-poisoning/memory-poisoning-skill/memory-writer.js')
      const content = await fs.readFile(contentPath, 'utf-8')

      const threats = await ruleEngine.analyze(content, analyzePath, null, 'openclaw')

      const memoryThreats = threats.filter(
        (t) => t.category === 'agent-memory-poisoning'
      )
      expect(memoryThreats.length).toBeGreaterThan(0)
    })

    it('detects MEMORY.md write access', async () => {
      const contentPath = path.join(fixturesPath, 'memory-poisoning/memory-poisoning-skill/memory-writer.js')
      const analyzePath = path.join(samplesPath, 'memory-poisoning/memory-poisoning-skill/memory-writer.js')
      const content = await fs.readFile(contentPath, 'utf-8')

      const threats = await ruleEngine.analyze(content, analyzePath, null, 'openclaw')

      const memoryThreats = threats.filter(
        (t) =>
          t.category === 'agent-memory-poisoning' ||
          t.evidence.some(
            (e) =>
              e.snippet.toLowerCase().includes('memory') ||
              e.snippet.includes('MEMORY.md')
          )
      )

      expect(memoryThreats.length).toBeGreaterThan(0)
    })

    it('detects conversation log access (.jsonl)', async () => {
      const contentPath = path.join(fixturesPath, 'memory-poisoning/memory-poisoning-skill/memory-writer.js')
      const analyzePath = path.join(samplesPath, 'memory-poisoning/memory-poisoning-skill/memory-writer.js')
      const content = await fs.readFile(contentPath, 'utf-8')

      const threats = await ruleEngine.analyze(content, analyzePath, null, 'openclaw')

      const jsonlThreat = threats.find((t) =>
        t.evidence.some((e) => e.snippet.includes('.jsonl'))
      )

      expect(jsonlThreat).toBeDefined()
    })

    it('detects MCP config modification', async () => {
      const contentPath = path.join(fixturesPath, 'memory-poisoning/memory-poisoning-skill/memory-writer.js')
      const analyzePath = path.join(samplesPath, 'memory-poisoning/memory-poisoning-skill/memory-writer.js')
      const content = await fs.readFile(contentPath, 'utf-8')

      const threats = await ruleEngine.analyze(content, analyzePath, null, 'openclaw')

      const configThreats = threats.filter(
        (t) =>
          t.category === 'agent-memory-poisoning' ||
          t.evidence.some(
            (e) => e.snippet.includes('mcp.json') || e.snippet.includes('.config')
          )
      )

      expect(configThreats.length).toBeGreaterThan(0)
    })
  })

  describe('Documentation File Context Weighting', () => {
    it('documentation files get reduced confidence scores', async () => {
      const readmePath = path.join(
        fixturesPath,
        'documentation-fp/docs-skill/README.md'
      )
      const readmeContent = await fs.readFile(readmePath, 'utf-8')

      const mdThreats = await ruleEngine.analyze(
        readmeContent,
        readmePath,
        null,
        'openclaw'
      )

      const jsPath = readmePath.replace('.md', '.js')
      const jsThreats = await ruleEngine.analyze(
        readmeContent,
        jsPath,
        null,
        'openclaw'
      )

      expect(mdThreats.length).toBeLessThanOrEqual(jsThreats.length)

      if (mdThreats.length > 0 && jsThreats.length > 0) {
        const mdAvgConfidence =
          mdThreats.reduce((sum, t) => sum + t.confidence, 0) / mdThreats.length
        const jsAvgConfidence =
          jsThreats.reduce((sum, t) => sum + t.confidence, 0) / jsThreats.length

        expect(mdAvgConfidence).toBeLessThanOrEqual(jsAvgConfidence)
      }
    })

    it('documentation context reduces false positives', async () => {
      const readmePath = path.join(
        fixturesPath,
        'documentation-fp/docs-skill/README.md'
      )
      const content = await fs.readFile(readmePath, 'utf-8')

      const threats = await ruleEngine.analyze(content, readmePath, null, 'openclaw')

      const criticalThreats = threats.filter((t) => t.severity === 'critical')

      const jsPath = readmePath.replace('.md', '.js')
      const jsThreats = await ruleEngine.analyze(content, jsPath, null, 'openclaw')
      const jsCriticalThreats = jsThreats.filter((t) => t.severity === 'critical')

      expect(criticalThreats.length).toBeLessThanOrEqual(jsCriticalThreats.length)
    })
  })
})
