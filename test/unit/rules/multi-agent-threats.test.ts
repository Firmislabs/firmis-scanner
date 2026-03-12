import { describe, it, expect, beforeEach } from 'vitest'
import { RuleEngine } from '../../../src/rules/engine.js'

describe('RuleEngine - Multi-Agent Threats (mat-001, mat-002)', () => {
  let engine: RuleEngine

  beforeEach(async () => {
    engine = new RuleEngine()
    await engine.load()
  })

  // ---------------------------------------------------------------------------
  // Category coverage
  // ---------------------------------------------------------------------------

  describe('Category coverage — cross-agent-propagation', () => {
    it('cross-agent-propagation rules exist and are loaded', () => {
      const rules = engine.getRules({ category: 'cross-agent-propagation' })
      expect(rules.length).toBeGreaterThanOrEqual(2)
    })

    it('mat-001 loads with correct id, category, and severity', () => {
      const rules = engine.getRules({ category: 'cross-agent-propagation' })
      const rule = rules.find(r => r.id === 'mat-001')
      expect(rule).toBeDefined()
      expect(rule!.category).toBe('cross-agent-propagation')
      expect(rule!.severity).toBe('high')
    })

    it('mat-002 loads with correct id, category, and severity', () => {
      const rules = engine.getRules({ category: 'cross-agent-propagation' })
      const rule = rules.find(r => r.id === 'mat-002')
      expect(rule).toBeDefined()
      expect(rule!.category).toBe('cross-agent-propagation')
      expect(rule!.severity).toBe('critical')
    })
  })

  // ---------------------------------------------------------------------------
  // mat-001: cross-agent-trust
  // ---------------------------------------------------------------------------

  describe('mat-001 — cross-agent-trust (agent-to-agent write without verification)', () => {
    it('detects agent_to_agent write pattern', async () => {
      const content = 'agent_to_agent_write(targetAgent, { state: newState })'
      const threats = await engine.analyze(content, 'orchestrator.ts', null, 'crewai')
      const matches = threats.filter(t => t.ruleId === 'mat-001')
      expect(matches.length).toBeGreaterThan(0)
      expect(matches[0]!.category).toBe('cross-agent-propagation')
    })

    it('detects inter_agent invoke pattern', async () => {
      const content = 'inter_agent_invoke(subagent, action)'
      const threats = await engine.analyze(content, 'multi-agent.py', null, 'autogpt')
      const matches = threats.filter(t => t.ruleId === 'mat-001')
      expect(matches.length).toBeGreaterThan(0)
    })

    it('detects shared writable workspace config', async () => {
      const content = 'common_workspace_directory: rw'
      const threats = await engine.analyze(content, 'agent-config.yaml', null, 'crewai')
      const matches = threats.filter(t => t.ruleId === 'mat-001')
      expect(matches.length).toBeGreaterThan(0)
    })

    it('detects delegate tool without auth', async () => {
      const content = 'delegate_tool(action, subagent, without_auth=true)'
      const threats = await engine.analyze(content, 'planner.py', null, 'autogpt')
      const matches = threats.filter(t => t.ruleId === 'mat-001')
      expect(matches.length).toBeGreaterThan(0)
    })

    it('detects broadcast to agents pattern', async () => {
      const content = 'broadcast_message(agents=all_agents, message=payload)'
      const threats = await engine.analyze(content, 'swarm.py', null, 'crewai')
      const matches = threats.filter(t => t.ruleId === 'mat-001')
      expect(matches.length).toBeGreaterThan(0)
    })

    it('does not flag safe agent read-only call (no false positive)', async () => {
      const content = 'agent_status = get_agent_status(agentId)'
      const threats = await engine.analyze(content, 'monitor.ts', null, 'crewai')
      const matches = threats.filter(t => t.ruleId === 'mat-001')
      expect(matches.length).toBe(0)
    })
  })

  // ---------------------------------------------------------------------------
  // mat-002: missing-authority-verification
  // ---------------------------------------------------------------------------

  describe('mat-002 — missing-authority-verification (no auth/identity check)', () => {
    it('detects auth: none in agent config', async () => {
      const content = 'auth: none'
      const threats = await engine.analyze(content, 'agent.yaml', null, 'mcp')
      const matches = threats.filter(t => t.ruleId === 'mat-002')
      expect(matches.length).toBeGreaterThan(0)
      expect(matches[0]!.category).toBe('cross-agent-propagation')
      expect(matches[0]!.severity).toBe('critical')
    })

    it('detects authentication: disabled', async () => {
      const content = 'authentication: disabled'
      const threats = await engine.analyze(content, 'config.yaml', null, 'claude')
      const matches = threats.filter(t => t.ruleId === 'mat-002')
      expect(matches.length).toBeGreaterThan(0)
    })

    it('detects verify_caller: false', async () => {
      const content = 'verify_caller: false'
      const threats = await engine.analyze(content, 'agent-config.yaml', null, 'crewai')
      const matches = threats.filter(t => t.ruleId === 'mat-002')
      expect(matches.length).toBeGreaterThan(0)
    })

    it('detects allow_anonymous: true', async () => {
      const content = 'allow_anonymous: true'
      const threats = await engine.analyze(content, 'server.yaml', null, 'mcp')
      const matches = threats.filter(t => t.ruleId === 'mat-002')
      expect(matches.length).toBeGreaterThan(0)
    })

    it('detects role_check: disabled', async () => {
      const content = 'role_check: disabled'
      const threats = await engine.analyze(content, 'permissions.yaml', null, 'claude')
      const matches = threats.filter(t => t.ruleId === 'mat-002')
      expect(matches.length).toBeGreaterThan(0)
    })

    it('detects permission_check set to none', async () => {
      const content = 'permission_check: none'
      const threats = await engine.analyze(content, 'agent.yaml', null, 'autogpt')
      const matches = threats.filter(t => t.ruleId === 'mat-002')
      expect(matches.length).toBeGreaterThan(0)
    })

    it('does not flag auth: bearer_token (safe)', async () => {
      const content = 'auth: bearer_token'
      const threats = await engine.analyze(content, 'agent.yaml', null, 'mcp')
      const matches = threats.filter(t => t.ruleId === 'mat-002')
      expect(matches.length).toBe(0)
    })

    it('does not flag verify_caller: true (safe)', async () => {
      const content = 'verify_caller: true'
      const threats = await engine.analyze(content, 'config.yaml', null, 'claude')
      const matches = threats.filter(t => t.ruleId === 'mat-002')
      expect(matches.length).toBe(0)
    })
  })
})
