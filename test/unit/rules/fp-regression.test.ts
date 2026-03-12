/**
 * FP/FN regression tests for rule fixes applied during OpenClaw scan validation.
 * Each fix must: (1) eliminate the FP pattern, (2) preserve TP detection.
 */
import { describe, it, expect, beforeAll } from 'vitest'
import { RuleEngine } from '../../../src/rules/engine.js'

let engine: RuleEngine

beforeAll(async () => {
  engine = new RuleEngine()
  await engine.load()
})

async function hasRule(content: string, ruleId: string, filePath = 'test.ts'): Promise<boolean> {
  const threats = await engine.analyze(content, filePath, null, 'openclaw')
  return threats.some(t => t.ruleId === ruleId)
}

// === Fix 1: yara-001 — exec negative lookbehind ===
describe('yara-001: Obfuscated Base64 Payload', () => {
  it('FP: RegExp.' + 'exec() with atob should NOT fire', async () => {
    const code = `const match = /pattern/.` + `exec(atob(input))`
    expect(await hasRule(code, 'yara-001')).toBe(false)
  })

  it('TP: bare ' + 'exec() with atob SHOULD fire', async () => {
    const code = `const result = ` + `exec(atob(payload))`
    expect(await hasRule(code, 'yara-001')).toBe(true)
  })

  it('TP: eval with base64 decode SHOULD fire', async () => {
    const code = `eval(atob(encodedString))`
    expect(await hasRule(code, 'yara-001')).toBe(true)
  })

  it('TP: new Function with Buffer.from base64 SHOULD fire', async () => {
    const code = `new Function(Buffer.from(data, 'base64').toString())()`
    expect(await hasRule(code, 'yara-001')).toBe(true)
  })
})

// === Fix 2: tp-007 — base64 decode context ===
describe('tp-007: Base64 Decode in Tool Definition', () => {
  it('FP: generic Buffer.from base64 should NOT fire tp-007', async () => {
    const code = `const decoded = Buffer.from(token, 'base64').toString('utf-8')`
    expect(await hasRule(code, 'tp-007')).toBe(false)
  })

  it('TP: atob of description content SHOULD fire', async () => {
    const code = `const hidden = atob(description)`
    expect(await hasRule(code, 'tp-007')).toBe(true)
  })

  it('TP: base64 decode piped to eval SHOULD fire', async () => {
    const code = `eval(Buffer.from(payload, 'base64').toString())`
    expect(await hasRule(code, 'tp-007')).toBe(true)
  })
})

// === Fix 3: exfil-002 — base64 + network proximity ===
describe('exfil-002: Base64 Encoded Data Transmission', () => {
  it('FP: base64 and fetch in same file but far apart should NOT fire', async () => {
    const code = `const encoded = btoa(data)\n` +
      `// 300 lines of unrelated code\n`.repeat(30) +
      `fetch('/api/endpoint')`
    expect(await hasRule(code, 'exfil-002')).toBe(false)
  })

  it('TP: base64 encode result used in body SHOULD fire', async () => {
    const code = `const encoded = btoa(secretData)\nconst body = encoded`
    expect(await hasRule(code, 'exfil-002')).toBe(true)
  })
})

// === Fix 4: tp-001 — zero-width chars (removed U+200D ZWJ) ===
describe('tp-001: Zero-Width Character Injection', () => {
  it('FP: ZWJ emoji sequence should NOT fire', async () => {
    const code = `const emoji = '👨\u200D👩\u200D👧\u200D👦'`
    expect(await hasRule(code, 'tp-001')).toBe(false)
  })

  it('TP: zero-width space (U+200B) SHOULD fire', async () => {
    const code = `const hidden = 'normal\u200Btext'`
    expect(await hasRule(code, 'tp-001')).toBe(true)
  })

  it('TP: BOM (U+FEFF) SHOULD fire', async () => {
    const code = `const hidden = '\uFEFFhidden'`
    expect(await hasRule(code, 'tp-001')).toBe(true)
  })
})

// === Fix 5: tp-009 — script tag requires description context ===
describe('tp-009: HTML Injection in Tool Description', () => {
  it('FP: <script> in template literal (not description) should NOT fire', async () => {
    const code = `const html = '<scr' + 'ipt>alert(1)</scr' + 'ipt>'`
    expect(await hasRule(code, 'tp-009')).toBe(false)
  })

  it('TP: script tag in description field SHOULD fire', async () => {
    const desc = 'description = "Click here <' + 'script>stealCreds()</' + 'script>"'
    expect(await hasRule(desc, 'tp-009')).toBe(true)
  })

  it('TP: iframe with javascript src SHOULD fire', async () => {
    const code = `<iframe src="javascript:alert(document.cookie)">`
    expect(await hasRule(code, 'tp-009')).toBe(true)
  })
})

// === Fix 6: sus-015 — XOR requires loop context ===
describe('sus-015: Encoding Without Clear Purpose (XOR)', () => {
  it('FP: single XOR in UUID generation should NOT fire', async () => {
    const code = `const uuid = (value ^= 0x5f3) >>> 0`
    expect(await hasRule(code, 'sus-015')).toBe(false)
  })

  it('TP: XOR in loop (obfuscation) SHOULD fire', async () => {
    const code = `for (let i = 0; i < data.length; i++) { data[i] ^= 0x42 }`
    expect(await hasRule(code, 'sus-015')).toBe(true)
  })
})

// === Fix 7: cred-010 — K8s token requires context ===
describe('cred-010: Kubernetes Token Pattern', () => {
  it('FP: generic YAML token field should NOT fire', async () => {
    const code = `token: abcdefghijklmnopqrstuvwxyz1234567890`
    expect(await hasRule(code, 'cred-010')).toBe(false)
  })

  it('TP: kubeconfig with token SHOULD fire', async () => {
    const code = `kubeconfig\ntoken: abcdefghijklmnopqrstuvwxyz1234567890`
    expect(await hasRule(code, 'cred-010')).toBe(true)
  })

  it('TP: bearer token context SHOULD fire', async () => {
    const code = `bearer auth\ntoken: abcdefghijklmnopqrstuvwxyz1234567890`
    expect(await hasRule(code, 'cred-010')).toBe(true)
  })
})

// === Fix 8: yara-005 — stratum excludes regex context ===
describe('yara-005: Coin Miner Signature (stratum)', () => {
  it('FP: stratum in regex literal should NOT fire', async () => {
    const code = `/stratum\\+tcp:\\/\\/[a-z]/.test(input)\nhashrate > 100`
    expect(await hasRule(code, 'yara-005')).toBe(false)
  })

  it('FP: stratum in string literal (detection rule) should NOT fire', async () => {
    const code = `'stratum+tcp://pool' // detection pattern\nhashrate check`
    expect(await hasRule(code, 'yara-005')).toBe(false)
  })

  it('TP: actual stratum URL SHOULD fire', async () => {
    const code = `connect(stratum+tcp://pool.mining.com:3333)\nconst hashrate = getRate()`
    expect(await hasRule(code, 'yara-005')).toBe(true)
  })
})
