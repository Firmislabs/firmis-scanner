#!/usr/bin/env bash
set -euo pipefail

# Compute stats from source files
RULE_COUNT=$(grep -r '^\s*- id:' rules/*.yaml | wc -l | tr -d ' ')
PLATFORM_COUNT=$(sed -n '/## Supported Platforms/,/^##[^#]/p' README.md | grep -c '| \*\*' || true)
CATEGORY_COUNT=$(grep -r '^\s*category:' rules/*.yaml | sed 's/.*category: *//' | sort -u | wc -l | tr -d ' ')
VERSION=$(node -p "require('./package.json').version")

echo "Stats: ${RULE_COUNT} rules, ${PLATFORM_COUNT} platforms, ${CATEGORY_COUNT} categories, v${VERSION}"

# Compute "X more platforms" — total minus the 3 named in intro (MCP, Claude, Codex)
MORE_PLATFORMS=$((PLATFORM_COUNT - 3))

# Detect OS for sed compatibility (macOS vs Linux)
if [[ "$(uname)" == "Darwin" ]]; then
  SED_INPLACE=(sed -i '')
else
  SED_INPLACE=(sed -i)
fi

# Update hero description
"${SED_INPLACE[@]}" -E "s|<!-- readme-stats -->.*<!-- /readme-stats -->|<!-- readme-stats -->Security scanner for AI agents. Scans MCP servers, Claude skills, Codex plugins, and ${MORE_PLATFORMS} more platforms for credential harvesting, prompt injection, tool poisoning, and $((CATEGORY_COUNT - 3)) other threat categories. ${RULE_COUNT} detection rules. Zero config.<!-- /readme-stats -->|" README.md

# Update diff comparison
"${SED_INPLACE[@]}" -E "s|<!-- readme-diff -->.*<!-- /readme-diff -->|<!-- readme-diff -->**How is it different from mcp-scan?** Firmis scans ${PLATFORM_COUNT} platforms (not just MCP), has ${RULE_COUNT} rules (not just config checks), and includes runtime monitoring capabilities.<!-- /readme-diff -->|" README.md

# Update features table
"${SED_INPLACE[@]}" -E "s|<!-- readme-features -->.*<!-- /readme-features -->|<!-- readme-features -->Scan for threats (${RULE_COUNT} rules, ${CATEGORY_COUNT} categories)<!-- /readme-features -->|" README.md

# Update version in example output blocks
"${SED_INPLACE[@]}" -E "s|Firmis Scanner v[0-9]+\.[0-9]+\.[0-9]+|Firmis Scanner v${VERSION}|g" README.md

echo "README updated successfully"
