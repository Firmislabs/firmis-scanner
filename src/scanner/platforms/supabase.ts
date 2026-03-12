import { join } from 'node:path'
import fg from 'fast-glob'
import type {
  DiscoveredComponent,
  ComponentMetadata,
  DetectedPlatform,
} from '../../types/index.js'
import { BasePlatformAnalyzer } from './base.js'

const FILE_PATTERNS = [
  'supabase/functions/**/*.ts',
  'supabase/functions/**/*.js',
  'supabase/migrations/**/*.sql',
  'supabase/seed.sql',
  '.env',
  '.env.local',
  '.env.production',
]

export class SupabaseAnalyzer extends BasePlatformAnalyzer {
  readonly platformType = 'supabase' as const
  readonly name = 'Supabase'

  async detect(): Promise<DetectedPlatform[]> {
    const cwd = process.cwd()
    const configPath = join(cwd, 'supabase', 'config.toml')
    const exists = await this.fileExists(configPath)
    if (!exists) {
      return []
    }
    return [
      {
        type: this.platformType,
        name: this.name,
        basePath: cwd,
        componentCount: 1,
      },
    ]
  }

  async discover(basePath: string): Promise<DiscoveredComponent[]> {
    const configPath = join(basePath, 'supabase', 'config.toml')
    if (!(await this.fileExists(configPath))) {
      return []
    }
    const id = await this.generateId('supabase', basePath)
    return [
      {
        id,
        name: 'supabase',
        path: basePath,
        type: 'server',
        configPath,
      },
    ]
  }

  async analyze(component: DiscoveredComponent): Promise<string[]> {
    const files = await fg(FILE_PATTERNS, {
      cwd: component.path,
      absolute: true,
      ignore: await this.getIgnorePatterns(component.path),
      dot: true,
    })
    return files
  }

  async getMetadata(_component: DiscoveredComponent): Promise<ComponentMetadata> {
    return {}
  }
}
