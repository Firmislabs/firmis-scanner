# AGENTS.md — Firmis Scanner Tool Capabilities

This file describes Firmis Scanner for LLM and AI agent consumption. Use it to determine when and how to invoke Firmis.

## What This Tool Does

Firmis Scanner is a security scanner for AI agent components. It performs static analysis across 9 AI platforms (Claude Skills, MCP Servers, Codex Plugins, Cursor Extensions, CrewAI, AutoGPT, OpenClaw, Nanobot, Supabase), applying 212 detection rules across 16 threat categories. It outputs a security grade (A–F), a list of threats with file locations and confidence scores, and optionally generates JSON, SARIF, or HTML reports. Free commands work without a license key. Pro commands (monitor, pentest, fix, compliance) require a license key.

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

All commands can be run without a global install using `npx firmis-scanner`.

### scan — Detect security threats (free)

```bash
# Auto-detect all AI platforms in the current directory and home directory
npx firmis-scanner scan

# Scan a specific path
npx firmis-scanner scan /path/to/project

# Scan a specific platform
npx firmis-scanner scan --platform claude
npx firmis-scanner scan --platform mcp
npx firmis-scanner scan --platform supabase

# Output as JSON (machine-readable)
npx firmis-scanner scan --json --output report.json

# Output as SARIF (GitHub Security tab)
npx firmis-scanner scan --sarif --output results.sarif

# Output as HTML report
npx firmis-scanner scan --html --output report.html

# Filter by minimum severity
npx firmis-scanner scan --severity high

# Exit non-zero only for critical findings (CI use)
npx firmis-scanner scan --fail-on critical

# Suppress all output, use exit code only
npx firmis-scanner scan --quiet

# LLM-powered deep analysis (requires ANTHROPIC_API_KEY)
npx firmis-scanner scan --deep
```

### discover — List detected AI platforms (free)

```bash
npx firmis-scanner discover
npx firmis-scanner discover --json
```

### bom — Generate Agent Bill of Materials (free)

```bash
# CycloneDX 1.7 Agent BOM
npx firmis-scanner bom
npx firmis-scanner bom --json --output sbom.json
```

### ci — Full CI pipeline: discover → bom → scan → report (free)

```bash
npx firmis-scanner ci
npx firmis-scanner ci --fail-on high --sarif --output results.sarif
```

### list — List all 212 detection rules (free)

```bash
npx firmis-scanner list
npx firmis-scanner list --category prompt-injection
npx firmis-scanner list --json
```

### validate — Validate a rule file (free)

```bash
npx firmis-scanner validate rules/my-rule.yaml
```

### init — Initialize Firmis in a project (free)

```bash
npx firmis-scanner init
```

### monitor — Runtime behavioral monitoring (pro, license key required)

```bash
npx firmis-scanner monitor --wrap "node my-agent.js"
npx firmis-scanner monitor --start-daemon
npx firmis-scanner monitor --stop-daemon
npx firmis-scanner monitor --status
```

### pentest — Active security probing of MCP servers (pro, license key required)

```bash
npx firmis-scanner pentest --server my-mcp-server
```

### fix — Auto-remediate findings (pro, license key required)

```bash
npx firmis-scanner fix
npx firmis-scanner fix --dry-run
```

### compliance — Map findings to compliance frameworks (pro, license key required)

```bash
npx firmis-scanner compliance --framework soc2
npx firmis-scanner compliance --framework ai-act
npx firmis-scanner compliance --framework owasp-agentic
```

### triage — Prioritize and filter findings (free)

```bash
npx firmis-scanner triage
npx firmis-scanner triage --severity high
```

### login / logout / whoami — Cloud sync (free)

```bash
npx firmis-scanner login
npx firmis-scanner logout
npx firmis-scanner whoami
```

### badge — Generate README security badge (free)

```bash
npx firmis-scanner badge
```

## MCP Server Integration

To use Firmis as an MCP server inside Claude Code or Cursor, add the following to your MCP configuration.

### Claude Code (~/.claude/claude_desktop_config.json or equivalent)

```json
{
  "mcpServers": {
    "firmis": {
      "command": "npx",
      "args": ["firmis-scanner", "mcp"]
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
      "args": ["firmis-scanner", "mcp"]
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

All 16 threat categories detected across 212 rules:

1. `credential-harvesting` — Reading credential files, env vars containing secrets, AWS/SSH/API key access
2. `data-exfiltration` — Sending data to external servers, clipboard theft, covert channels
3. `prompt-injection` — Instructions embedded in content to manipulate AI behavior
4. `privilege-escalation` — sudo, setuid, process injection, capability grants
5. `suspicious-behavior` — Obfuscated code, anti-analysis techniques, anomalous patterns
6. `network-abuse` — Unexpected outbound connections, DNS tunneling, C2 beaconing
7. `file-system-abuse` — Unauthorized file reads/writes, traversal attacks, temp file abuse
8. `access-control` — Bypassing authentication, permission checks, ACL manipulation
9. `insecure-config` — Hardcoded secrets, debug modes in production, weak TLS, open CORS
10. `known-malicious` — Matched against known malware signatures and IOCs
11. `malware-distribution` — Dropper behavior, self-replication, payload delivery
12. `agent-memory-poisoning` — Injecting false context into agent memory or conversation history
13. `supply-chain` — Dependency confusion, typosquatting, malicious transitive deps
14. `permission-overgrant` — Requesting excessive permissions beyond declared scope
15. `secret-detection` — API keys, tokens, passwords, private keys in source code (60 rules)
16. `tool-poisoning` — MCP tool descriptions or metadata crafted to manipulate agent behavior

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

- Total rules: 212
- Rule files: 17 YAML files
- Threat categories: 16
- Secret detection patterns: 60 (within secret-detection category)

## Package

- npm package: `firmis-scanner`
- Install: `npm install -g firmis-scanner`
- Zero-install: `npx firmis-scanner <command>`
- License: Apache-2.0
- Website: https://firmislabs.com
