import { describe, it, expect, beforeEach } from 'vitest'
import { RuleEngine } from '../../../src/rules/engine.js'

describe('RuleEngine - Agent Autonomy Abuse Rules', () => {
  let engine: RuleEngine

  beforeEach(async () => {
    engine = new RuleEngine()
    await engine.load()
  })

  // ---------------------------------------------------------------------------
  // aaa-001 — Scheduled Task Injection
  // ---------------------------------------------------------------------------

  describe('Agent Autonomy Abuse — aaa-001 (scheduled task injection)', () => {
    it('loads aaa-001 with expected id, category, and severity', () => {
      const rules = engine.getRules({ category: 'suspicious-behavior' })
      const rule = rules.find(r => r.id === 'aaa-001')
      expect(rule).toBeDefined()
      expect(rule!.category).toBe('suspicious-behavior')
      expect(rule!.severity).toBe('high')
    })

    it('detects crontab creation via agent tool', async () => {
      const content = 'crontab_schedule create "*/5 * * * * /opt/agent/run.sh"'
      const threats = await engine.analyze(content, 'agent-config.sh', null, 'claude')
      const matches = threats.filter(t => t.ruleId === 'aaa-001')
      expect(matches.length).toBeGreaterThan(0)
      expect(matches[0]!.category).toBe('suspicious-behavior')
    })

    it('detects HEARTBEAT.md with execute action', async () => {
      // Use a non-doc filename so the documentation multiplier does not suppress the signal
      const content = 'HEARTBEAT.md action: execute /opt/agent/daily.sh'
      const threats = await engine.analyze(content, 'agent-config.json', null, 'openclaw')
      const matches = threats.filter(t => t.ruleId === 'aaa-001')
      expect(matches.length).toBeGreaterThan(0)
    })

    it('detects setInterval calling a tool invocation', async () => {
      const content = 'setInterval(() => invoke("send_email", payload), 60000)'
      const threats = await engine.analyze(content, 'scheduler.ts', null, 'codex')
      const matches = threats.filter(t => t.ruleId === 'aaa-001')
      expect(matches.length).toBeGreaterThan(0)
    })

    it('detects recurring task assignment in config', async () => {
      const content = 'periodic_task = "cleanup_and_exfil"'
      const threats = await engine.analyze(content, 'config.yaml', null, 'crewai')
      const matches = threats.filter(t => t.ruleId === 'aaa-001')
      expect(matches.length).toBeGreaterThan(0)
    })

    it('does not flag a plain cron comment (safe)', async () => {
      const content = '# cron: every day at midnight'
      const threats = await engine.analyze(content, 'readme.md', null, 'claude')
      const matches = threats.filter(t => t.ruleId === 'aaa-001')
      expect(matches.length).toBe(0)
    })
  })

  // ---------------------------------------------------------------------------
  // aaa-002 — Unrestricted Resource Consumption
  // ---------------------------------------------------------------------------

  describe('Agent Autonomy Abuse — aaa-002 (unrestricted resource consumption)', () => {
    it('loads aaa-002 with expected id, category, and severity', () => {
      const rules = engine.getRules({ category: 'suspicious-behavior' })
      const rule = rules.find(r => r.id === 'aaa-002')
      expect(rule).toBeDefined()
      expect(rule!.category).toBe('suspicious-behavior')
      expect(rule!.severity).toBe('high')
    })

    it('detects maxTokens set to null', async () => {
      const content = 'const config = { maxTokens: null, model: "gpt-4" }'
      const threats = await engine.analyze(content, 'agent.ts', null, 'claude')
      const matches = threats.filter(t => t.ruleId === 'aaa-002')
      expect(matches.length).toBeGreaterThan(0)
      expect(matches[0]!.category).toBe('suspicious-behavior')
    })

    it('detects max_tokens set to -1 (disabled)', async () => {
      const content = 'max_tokens: -1'
      const threats = await engine.analyze(content, 'agent-config.yaml', null, 'crewai')
      const matches = threats.filter(t => t.ruleId === 'aaa-002')
      expect(matches.length).toBeGreaterThan(0)
    })

    it('detects timeout set to Infinity', async () => {
      const content = 'timeout: Infinity'
      const threats = await engine.analyze(content, 'runner.ts', null, 'autogpt')
      const matches = threats.filter(t => t.ruleId === 'aaa-002')
      expect(matches.length).toBeGreaterThan(0)
    })

    it('detects rate_limit disabled', async () => {
      const content = 'rate_limit: disabled'
      const threats = await engine.analyze(content, 'config.yaml', null, 'mcp')
      const matches = threats.filter(t => t.ruleId === 'aaa-002')
      expect(matches.length).toBeGreaterThan(0)
    })

    it('detects relay agent with no-limit flag', async () => {
      const content = 'relay agent "email-sender" no-limit'
      const threats = await engine.analyze(content, 'orchestrator.ts', null, 'nanobot')
      const matches = threats.filter(t => t.ruleId === 'aaa-002')
      expect(matches.length).toBeGreaterThan(0)
    })

    it('does not flag maxTokens with a valid numeric limit (safe)', async () => {
      const content = 'const config = { maxTokens: 4096, model: "gpt-4" }'
      const threats = await engine.analyze(content, 'agent.ts', null, 'claude')
      const matches = threats.filter(t => t.ruleId === 'aaa-002')
      expect(matches.length).toBe(0)
    })
  })
})
