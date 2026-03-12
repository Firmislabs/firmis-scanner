/**
 * Maximum files scanned per component. With DEFAULT_IGNORE_GLOBS
 * filtering out build/vendor/generated files, we can safely set
 * this higher than the previous 500.
 */
export const MAX_FILES_PER_COMPONENT = 5000

/**
 * Maximum content size (in bytes) passed to rule matchers.
 * Files larger than this are truncated — attack patterns appear
 * in the first few KB, not in the middle of a 5MB generated file.
 * The full file is still read for AST parsing (JS/TS only).
 */
export const MAX_CONTENT_SIZE = 50 * 1024 // 50KB

/**
 * Default file exclusion globs applied to all platform analyzers.
 * These skip files that are never useful for security scanning:
 * build output, dependencies, generated code, lock files, etc.
 */
export const DEFAULT_IGNORE_GLOBS: string[] = [
  // Dependencies & package managers
  '**/node_modules/**',
  '**/.git/**',
  '**/venv/**',
  '**/.venv/**',
  '**/__pycache__/**',
  '**/vendor/**',
  '**/.bundle/**',

  // Build output
  '**/dist/**',
  '**/build/**',
  '**/out/**',
  '**/.next/**',
  '**/.nuxt/**',
  '**/.output/**',
  '**/.svelte-kit/**',

  // Generated / compiled files
  '**/*.min.js',
  '**/*.min.css',
  '**/*.d.ts',
  '**/*.map',
  '**/*.bundle.js',
  '**/*.chunk.js',

  // Lock files (machine-generated, no attack surface)
  '**/package-lock.json',
  '**/yarn.lock',
  '**/pnpm-lock.yaml',
  '**/Cargo.lock',
  '**/poetry.lock',
  '**/Pipfile.lock',
  '**/composer.lock',
  '**/Gemfile.lock',
  '**/go.sum',

  // Test coverage & CI artifacts
  '**/coverage/**',
  '**/.nyc_output/**',
  '**/.cache/**',
  '**/.turbo/**',

  // IDE & OS
  '**/.idea/**',
  '**/.vscode/**',
  '**/.DS_Store',
  '**/Thumbs.db',
]
