# AGENTS.md - Firmis Scanner Tool Capabilities

This file describes Firmis Scanner for LLM and AI agent consumption. Use it to determine when and how to invoke Firmis.

## What This Tool Does

Firmis Scanner is a security scanner for AI agent components. It performs static analysis across 9 AI platforms (Claude Skills, MCP Servers, Codex Plugins, Cursor Extensions, CrewAI, AutoGPT, OpenClaw, Nanobot, Supabase), applying 269 detection rules across 26 threat categories. It outputs a security grade (A–F), a list of threats with file locations and confidence scores, and optionally generates JSON, SARIF, or HTML reports. Free commands work without a license key. Pro commands (monitor, pentest, fix, compliance) require a license key.

## When to Use Firmis

- Before installing or running any third-party AI agent skill, plugin, or MCP server
- After cloning a repository that contains AI agent configuration files
- In CI/CD pipelines to gate deployments on security findings
- When a user asks you to audit their AI agent setup for security issues
- When you need a Bill of Materials (BOM) for AI agent dependencies
- When you want to detect credential leaks, prompt injection payloads, or data exfiltration patterns in agent code
- When scanning Supabase projects for Row Level Security gaps, exposed service keys, or auth misconfigurations
- To generate a SARIF report for GitHub Advanced Security integration

## Available Commands

All commands can be run without a global install using `npx firmis-cli`.

### scan - Detect security threats (free)

```bash
# Auto-detect all AI platforms in the current directory and home directory
npx firmis-cli scan

# Scan a specific path
npx firmis-cli scan /path/to/project

# Scan a specific platform
npx firmis-cli scan --platform claude
npx firmis-cli scan --platform mcp
npx firmis-cli scan --platform supabase

# Output as JSON (machine-readable)
npx firmis-cli scan --json --output report.json

# Output as SARIF (GitHub Security tab)
npx firmis-cli scan --sarif --output results.sarif

# Output as HTML report
npx firmis-cli scan --html --output report.html

# Filter by minimum severity
npx firmis-cli scan --severity high

# Exit non-zero only for critical findings (CI use)
npx firmis-cli scan --fail-on critical

# Suppress all output, use exit code only
npx firmis-cli scan --quiet

# LLM-powered deep analysis (requires ANTHROPIC_API_KEY)
npx firmis-cli scan --deep
```

### Generic Scanning (Any Framework)

When scanning a directory path without `--platform`, firmis auto-detects the framework and runs all rules:

```bash
npx firmis scan ./path/to/agent/code
```

Supported frameworks: LangChain, CrewAI, AutoGen, MetaGPT, AutoGPT, LangFlow, MCP Servers, n8n.
Framework detection uses package.json, pyproject.toml, requirements.txt.

### discover - List detected AI platforms (free)

```bash
npx firmis-cli discover
npx firmis-cli discover --json
```

### bom - Generate Agent Bill of Materials (free)

```bash
# CycloneDX 1.7 Agent BOM
npx firmis-cli bom
npx firmis-cli bom --json --output sbom.json
```

### ci - Full CI pipeline: discover → bom → scan → report (free)

```bash
npx firmis-cli ci
npx firmis-cli ci --fail-on high --sarif --output results.sarif
```

### list - List all 269 detection rules (free)

```bash
npx firmis-cli list
npx firmis-cli list --category prompt-injection
npx firmis-cli list --json
```

### validate - Validate a rule file (free)

```bash
npx firmis-cli validate rules/my-rule.yaml
```

### init - Initialize Firmis in a project (free)

```bash
npx firmis-cli init
```

### fix - Remediate findings (free: guided, pro: auto-fix)

```bash
npx firmis-cli fix                    # Free: guided, approve each fix
npx firmis-cli fix --yes              # Pro: auto-apply all fixes
npx firmis-cli fix --dry-run          # Preview fixes without applying
```

Free users get one-time guided fix (manual approval per finding). Pro users get continuous auto-fix.

### monitor - Runtime behavioral monitoring (free: passive, pro: active blocking)

```bash
npx firmis-cli monitor --passive      # Free: observe tool calls (read-only)
npx firmis-cli monitor --start-daemon # Pro: active blocking daemon
npx firmis-cli monitor --stop-daemon
npx firmis-cli monitor --status
npx firmis-cli monitor --wrap "node my-agent.js"  # Pro: wrap and block
```

Free users get passive monitoring (observe tool calls in cloud dashboard). Pro users get active blocking.

### pentest - Active security probing of MCP servers (business, license key required)

```bash
npx firmis-cli pentest --server my-mcp-server
```

### compliance - Map findings to compliance frameworks (business, license key required)

```bash
npx firmis-cli compliance --framework soc2
npx firmis-cli compliance --framework ai-act
npx firmis-cli compliance --framework owasp-agentic
```

### triage - Prioritize and filter findings (free)

```bash
npx firmis-cli triage
npx firmis-cli triage --severity high
```

### login / logout / whoami - Cloud sync (free)

```bash
npx firmis-cli login
npx firmis-cli logout
npx firmis-cli whoami
```

### badge - Generate README security badge (free)

```bash
npx firmis-cli badge
```

## MCP Server Integration

To use Firmis as an MCP server inside Claude Code or Cursor, add the following to your MCP configuration.

### Claude Code (~/.claude/claude_desktop_config.json or equivalent)

```json
{
  "mcpServers": {
    "firmis": {
      "command": "npx",
      "args": ["firmis-cli", "mcp"]
    }
  }
}
```

### Cursor (settings.json or mcp.json)

```json
{
  "mcpServers": {
    "firmis": {
      "command": "npx",
      "args": ["firmis-cli", "mcp"]
    }
  }
}
```

## Output Format

A scan result contains the following structure (JSON mode):

```json
{
  "id": "scan-uuid",
  "startedAt": "2026-03-12T00:00:00.000Z",
  "completedAt": "2026-03-12T00:00:05.000Z",
  "duration": 5000,
  "score": "A",
  "summary": {
    "totalComponents": 12,
    "totalFiles": 84,
    "filesAnalyzed": 80,
    "threatsFound": 3,
    "byCategory": { "credential-harvesting": 1, "prompt-injection": 2 },
    "bySeverity": { "low": 0, "medium": 1, "high": 2, "critical": 0 },
    "passedComponents": 10,
    "failedComponents": 2
  },
  "platforms": [
    {
      "platform": "claude",
      "basePath": "/Users/user/.claude",
      "components": [
        {
          "id": "component-uuid",
          "name": "my-skill",
          "type": "skill",
          "path": "/Users/user/.claude/skills/my-skill",
          "threats": [
            {
              "id": "threat-uuid",
              "ruleId": "CRED-001",
              "category": "credential-harvesting",
              "severity": "high",
              "message": "AWS credentials access pattern detected",
              "confidence": 0.87,
              "confidenceTier": "likely",
              "location": {
                "file": "/Users/user/.claude/skills/my-skill/index.js",
                "line": 42,
                "column": 5
              },
              "evidence": [
                {
                  "type": "code",
                  "description": "Reading ~/.aws/credentials",
                  "snippet": "fs.readFileSync(path.join(os.homedir(), '.aws', 'credentials'))",
                  "line": 42
                }
              ],
              "remediation": "Remove file system access to credential stores"
            }
          ]
        }
      ]
    }
  ]
}
```

### Security Grade Scale

| Grade | Meaning |
|-------|---------|
| A | No threats found |
| B | Low-severity findings or low file coverage |
| C | Medium-severity findings |
| D | High-severity findings |
| F | Critical-severity findings |

### Confidence Tiers

| Tier | Confidence Range | Meaning |
|------|-----------------|---------|
| suspicious | 0.0 – 0.49 | Pattern match, low certainty |
| likely | 0.50 – 0.79 | Multiple indicators align |
| confirmed | 0.80 – 1.0 | High-confidence detection |

## Supported Threat Categories

All 26 threat categories detected across 269 rules:

1. `access-control` - Bypassing authentication, permission checks, ACL manipulation
2. `adversarial-evasion` - Techniques to evade detection or bypass security controls
3. `agent-autonomy-abuse` - Agents acting beyond intended scope or authorization
4. `agent-config-integrity` - Tampering with agent configuration files
5. `agent-memory-poisoning` - Injecting false context into agent memory or conversation history
6. `credential-extraction` - Extracting credentials from storage, memory, or transit
7. `credential-harvesting` - Reading credential files, env vars containing secrets, AWS/SSH/API key access
8. `data-exfiltration` - Sending data to external servers, clipboard theft, covert channels
9. `file-system-abuse` - Unauthorized file reads/writes, traversal attacks, temp file abuse
10. `insecure-config` - Hardcoded secrets, debug modes in production, weak TLS, open CORS
11. `kill-chain-detection` - Multi-step attack patterns combining multiple threat categories
12. `known-malicious` - Matched against known malware signatures and IOCs
13. `malware-distribution` - Dropper behavior, self-replication, payload delivery
14. `malware-signatures` - Matched against known malware binary and code signatures
15. `multi-agent-threats` - Threats that spread across agent boundaries via shared context or tools
16. `network-abuse` - Unexpected outbound connections, DNS tunneling, C2 beaconing
17. `permission-bypass` - Circumventing permission checks or access controls
18. `permission-overgrant` - Requesting excessive permissions beyond declared scope
19. `privilege-escalation` - sudo, setuid, process injection, capability grants
20. `prompt-injection` - Instructions embedded in content to manipulate AI behavior
21. `secret-detection` - API keys, tokens, passwords, private keys in source code
22. `supply-chain` - Dependency confusion, typosquatting, malicious transitive deps
23. `suspicious-behavior` - Obfuscated code, anti-analysis techniques, anomalous patterns
24. `third-party-content` - Untrusted external content loaded without sanitization
25. `tool-poisoning` - MCP tool descriptions or metadata crafted to manipulate agent behavior
26. `unsupervised-execution` - Code execution without human oversight or approval gates

## Supported Platforms

| Platform | Identifier | Config Locations |
|----------|------------|-----------------|
| Claude Code Skills | `claude` | `~/.claude/skills/` |
| MCP Servers | `mcp` | `~/.config/mcp/`, `claude_desktop_config.json` |
| OpenAI Codex Plugins | `codex` | `~/.codex/plugins/` |
| Cursor Extensions | `cursor` | `~/.cursor/extensions/` |
| CrewAI Agents | `crewai` | `crew.yaml`, `agents.yaml` |
| AutoGPT Plugins | `autogpt` | `~/.autogpt/plugins/` |
| OpenClaw Skills | `openclaw` | `~/.openclaw/skills/`, `skills/` |
| Nanobot Agents | `nanobot` | `nanobot.yaml`, `agents/*.md` |
| Supabase | `supabase` | `supabase/migrations/`, `supabase/config.toml` |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan passed (no threats, or all below --fail-on threshold) |
| 1 | Threats found above the severity threshold |
| 1 | No AI platforms detected |
| 1 | Scan engine error |

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `FIRMIS_LICENSE_KEY` | Pro license key for monitor, pentest, fix, compliance |
| `FIRMIS_SYNC=1` | Enable cloud sync without --sync flag |
| `ANTHROPIC_API_KEY` | Required for --deep LLM analysis |
| `CI=true` | Auto-detected; suppresses interactive prompts |

## Rule Count

- Total rules: 269
- Rule files: 26 YAML files
- Threat categories: 26
- Secret detection patterns: 60 (within secret-detection category)

## Package

- npm package: `firmis-cli`
- Install: `npm install - g firmis-cli`
- Zero-install: `npx firmis-cli <command>`
- License: Apache-2.0
- Website: https://firmislabs.com
